//! Executable, no-clock adapter for the authenticated upstream corpus.

use std::{
    collections::{BTreeMap, BTreeSet},
    fs,
    io::Write,
    path::Path,
};

use bstr::ByteVec;
use fre::{
    BuildError, CaptureAggregateLimits, CaptureBuildError, CaptureBuilder, CaptureMatchKind,
    CaptureRegex, CaptureSearchConfig, CaptureSearchLimits, CaptureSpan, CaptureWindow, PlanKind,
    PortableBuilder, PortableRegex, PortableRegexSet, PortableRegexSetBuildError,
    PortableRegexSetBuilder, PortableRegexSetRunLimits, PortableTextBuildError,
    PortableTextBuilder, PortableTextCaptureBuildError, PortableTextCaptureBuilder,
    PortableTextCaptureRegex, PortableTextCaptures, PortableTextRegex, PortableTextRegexSet,
    PortableTextRegexSetBuildError, PortableTextRegexSetBuilder, PortableTextSearchError,
    RustProfile, SearchError, SearchLimits, SearchWindow,
};
use fre_syntax::ErrorCategory;
use serde::{Deserialize, Serialize};

use crate::{
    AdapterDisposition, AdapterReceipt, AdapterSurface, CapabilityId, CaseAdapter, CaseReceipt,
    CorpusMembership, Inventory, InventoryError, MatchKind, NotApplicableReason, RawCase, RawSuite,
    SearchKind, SourceFileKind, UPSTREAM_REVISION, authenticate_git_checkout,
    build_inventory_from_authenticated_source, git_output, is_commit_oid, run_adapter_scaffold,
    sha256, validate_disposition,
};

/// Stable adapter report schema.
pub const ADAPTER_REPORT_SCHEMA: &str = "fre.upstream-rust-regex.adapter-report.v1";
/// Stable implementation identity for this portable-facade adapter.
pub const ADAPTER_ID: &str = "fre-portable-rust-facade-v29-overlapping-leftmost-all";

const LIMITATIONS: [&str; 7] = [
    "the production FRE Rust text matcher and RegexSet are restricted to finite languages proved byte-equivalent or identical UTF-8 HIRs with boundary-safe contextual search semantics",
    "the production FRE Rust text capture iterator requires an exact UTF-8-safe RustText/RustBytes HIR; certified text and bytes persistent-history captures preserve original-haystack assertion context across bounded search windows",
    "singleton RegexSet observations may delegate to the corresponding qualified single-pattern facade across selection policies while preserving exact anchoring, bounds, UTF-8, and match-limit semantics; these rows do not claim native set execution",
    "UTF-8 bytes capture observations may delegate only through the exact UTF-8-safe text capture facade and do not claim native bytes-engine UTF-8 capture execution",
    "RegexSet compile acceptance is independent of search and match-selection policy for every pattern count; UTF-8 bytes compilation may delegate to the corresponding qualified text RegexSet compiler after exact UTF-8 profile proof and does not expose native bytes-set execution",
    "set is-match may ignore search and match-selection policy only for unanchored full-haystack existence; selection-sensitive multi-pattern set which uses an adapter-only repeated constituent-search correctness fallback (up to O(patterns × haystack positions) facade search calls, each over a remaining window) for leftmost-first ordered-union and exact-literal leftmost/all selection, not a native or fast production RegexSet engine; UTF-8 bytes rows delegate through the qualified text proof and do not claim native bytes-set execution",
    "single-pattern compile acceptance and match existence are independent of upstream match-selection and iteration policy; span and capture observations support exact non-overlapping leftmost-first, earliest-end and leftmost/all search plus bounded correctness-oriented overlapping enumeration through exact-span capture queries (up to O(haystack squared) facade calls), not a native streaming overlapping engine; other policies remain rejected",
];

/// Half-open search range decoded from one upstream case.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct SearchBounds {
    pub start: usize,
    pub end: usize,
}

/// One expected half-open byte span.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ExpectedSpan {
    pub start: usize,
    pub end: usize,
}

/// One expected match with all participating or absent capture slots.
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct ExpectedCaptures {
    pub pattern_id: usize,
    pub groups: Vec<Option<ExpectedSpan>>,
}

/// Authenticated executable inputs joined to one inventory receipt.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ExecutableCase {
    pub id: String,
    pub patterns: Vec<String>,
    pub haystack: Vec<u8>,
    pub bounds: SearchBounds,
    pub line_terminator: u8,
    pub expected: Vec<ExpectedCaptures>,
}

/// Exact clean candidate source identity recorded in the report.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct CandidateIdentity {
    pub revision: String,
    pub tree: String,
    pub tracked_and_untracked_worktree_clean: bool,
}

/// Complete disposition cardinalities. `total` must equal the inventory's
/// mandatory obligation count.
#[derive(Clone, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct AdapterDispositionCounts {
    pub pass: usize,
    pub mismatch: usize,
    pub unsupported: usize,
    pub not_applicable: usize,
    pub fault: usize,
    pub total: usize,
}

/// Payload authenticated by [`AdapterReport::payload_sha256`].
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct AdapterReportPayload {
    pub upstream_revision: String,
    pub inventory_payload_sha256: String,
    pub adapter_id: String,
    pub candidate: CandidateIdentity,
    pub counts: AdapterDispositionCounts,
    pub receipts: Vec<AdapterReceipt>,
    pub limitations: Vec<String>,
}

/// Immutable complete adapter report.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct AdapterReport {
    pub schema: String,
    pub payload_sha256: String,
    pub payload: AdapterReportPayload,
}

/// Real adapter for the currently exposed FRE portable Rust-bytes facade.
#[derive(Debug)]
pub struct FreRegexAdapter {
    cases: BTreeMap<String, ExecutableCase>,
}

impl FreRegexAdapter {
    /// Bind the adapter to the complete authenticated executable corpus.
    pub fn new(cases: BTreeMap<String, ExecutableCase>) -> Result<Self, InventoryError> {
        if cases.len() != crate::EXPECTED_RUST_REGEX_CASES {
            return Err(InventoryError::new(format!(
                "executable corpus has {} cases, expected {}",
                cases.len(),
                crate::EXPECTED_RUST_REGEX_CASES
            )));
        }
        Ok(Self { cases })
    }
}

impl CaseAdapter for FreRegexAdapter {
    fn execute(&mut self, surface: AdapterSurface, case: &CaseReceipt) -> AdapterDisposition {
        let Some(input) = self.cases.get(&case.id) else {
            return fault("adapter.executable-case-missing");
        };
        execute_case(surface, case, input)
    }
}

fn execute_case(
    surface: AdapterSurface,
    case: &CaseReceipt,
    input: &ExecutableCase,
) -> AdapterDisposition {
    if let Err(reason) = surface_applicability(surface, case, input) {
        return AdapterDisposition::NotApplicable { reason };
    }
    match surface {
        AdapterSurface::RustTextCompile => execute_text_compile(case, input),
        AdapterSurface::RustTextIsMatch => execute_text_is_match(case, input),
        AdapterSurface::RustTextFindIter => execute_text_find(case, input),
        AdapterSurface::RustTextCapturesIter => execute_text_captures(case, input),
        AdapterSurface::RustBytesCapturesIter if case.utf8 => execute_text_captures(case, input),
        AdapterSurface::RustBytesCapturesIter => execute_bytes_captures(case, input),
        AdapterSurface::RustTextSetCompile => execute_text_set_compile(case, input),
        surface @ (AdapterSurface::RustTextSetIsMatch | AdapterSurface::RustTextSetWhich)
            if singleton_set_delegate_applicability(surface, case, input).is_ok() =>
        {
            execute_text_singleton_set_observation(surface, case, input)
        }
        AdapterSurface::RustTextSetWhich
            if multi_pattern_set_selection_applicability(case, input, true).is_ok() =>
        {
            execute_text_selected_set_which(case, input)
        }
        AdapterSurface::RustTextSetIsMatch => execute_text_set_is_match(case, input),
        AdapterSurface::RustTextSetWhich => execute_text_set_which(case, input),
        AdapterSurface::RustBytesSetCompile if case.utf8 => execute_text_set_compile(case, input),
        AdapterSurface::RustBytesSetCompile => execute_bytes_set_compile(case, input),
        surface @ (AdapterSurface::RustBytesSetIsMatch | AdapterSurface::RustBytesSetWhich)
            if case.utf8 && singleton_set_delegate_applicability(surface, case, input).is_ok() =>
        {
            execute_text_singleton_set_observation(surface, case, input)
        }
        surface @ (AdapterSurface::RustBytesSetIsMatch | AdapterSurface::RustBytesSetWhich)
            if singleton_set_delegate_applicability(surface, case, input).is_ok() =>
        {
            execute_bytes_singleton_set_observation(surface, case, input)
        }
        AdapterSurface::RustBytesSetWhich
            if case.utf8
                && multi_pattern_set_selection_applicability(case, input, false).is_ok() =>
        {
            execute_text_selected_set_which(case, input)
        }
        AdapterSurface::RustBytesSetWhich
            if multi_pattern_set_selection_applicability(case, input, false).is_ok() =>
        {
            execute_bytes_selected_set_which(case, input)
        }
        AdapterSurface::RustBytesSetIsMatch
            if case.utf8
                && selection_invariant_set_observation_applicability(
                    AdapterSurface::RustBytesSetIsMatch,
                    case,
                    input,
                    false,
                )
                .is_ok() =>
        {
            execute_text_set_is_match(case, input)
        }
        AdapterSurface::RustBytesSetWhich
            if utf8_bytes_overlapping_all_set_which_applicability(case, input).is_ok() =>
        {
            execute_text_set_which(case, input)
        }
        AdapterSurface::RustBytesSetWhich
            if case.utf8
                && selection_invariant_set_observation_applicability(
                    AdapterSurface::RustBytesSetWhich,
                    case,
                    input,
                    false,
                )
                .is_ok() =>
        {
            execute_text_set_which(case, input)
        }
        AdapterSurface::RustBytesSetIsMatch => execute_bytes_set_is_match(case, input),
        AdapterSurface::RustBytesSetWhich => execute_bytes_set_which(case, input),
        AdapterSurface::RustBytesCompile => execute_bytes_compile(case, input),
        AdapterSurface::RustBytesIsMatch if case.utf8 => execute_text_is_match(case, input),
        AdapterSurface::RustBytesFindIter if case.utf8 => execute_text_find(case, input),
        AdapterSurface::RustBytesIsMatch => execute_bytes_is_match(case, input),
        AdapterSurface::RustBytesFindIter => execute_bytes_find(case, input),
    }
}

/// Load executable inputs only after both the checkout and checked-in
/// inventory have independently authenticated the exact pinned source.
pub fn load_executable_cases(
    checkout: &Path,
    inventory: &Inventory,
) -> Result<BTreeMap<String, ExecutableCase>, InventoryError> {
    inventory.validate()?;
    authenticate_git_checkout(checkout, UPSTREAM_REVISION)?;
    let rebuilt = build_inventory_from_authenticated_source(checkout)?;
    if rebuilt != *inventory {
        return Err(InventoryError::new(
            "executable source differs from the checked-in inventory",
        ));
    }
    let receipts = inventory
        .payload
        .cases
        .iter()
        .map(|case| (case.id.as_str(), case))
        .collect::<BTreeMap<_, _>>();
    let mut cases = BTreeMap::new();
    for source_receipt in &inventory.payload.source_files {
        if source_receipt.kind != SourceFileKind::RustRegexCorpusToml {
            continue;
        }
        let source_path = checkout.join("testdata").join(&source_receipt.path);
        let bytes = fs::read(&source_path).map_err(|error| {
            InventoryError::new(format!(
                "read executable source {}: {error}",
                source_path.display()
            ))
        })?;
        if sha256(&bytes) != source_receipt.sha256 {
            return Err(InventoryError::new(format!(
                "executable source digest mismatch for {}",
                source_receipt.path
            )));
        }
        let source = std::str::from_utf8(&bytes).map_err(|error| {
            InventoryError::new(format!(
                "executable source {} is not UTF-8: {error}",
                source_receipt.path
            ))
        })?;
        let suite: RawSuite = toml::from_str(source).map_err(|error| {
            InventoryError::new(format!(
                "decode executable source {}: {error}",
                source_receipt.path
            ))
        })?;
        let base = source_receipt
            .path
            .strip_suffix(".toml")
            .ok_or_else(|| InventoryError::new("executable corpus path lacks .toml"))?;
        let mut unnamed = 0_usize;
        for raw in suite.tests {
            let name = if raw.name.is_empty() {
                unnamed = unnamed
                    .checked_add(1)
                    .ok_or_else(|| InventoryError::new("executable unnamed counter overflow"))?;
                unnamed.to_string()
            } else {
                raw.name.clone()
            };
            let id = format!("{base}/{name}");
            let receipt = receipts.get(id.as_str()).ok_or_else(|| {
                InventoryError::new(format!("executable case has no inventory receipt: {id}"))
            })?;
            let raw_hash = sha256(&serde_json::to_vec(&raw).map_err(|error| {
                InventoryError::new(format!("encode executable case {id}: {error}"))
            })?);
            if raw_hash != receipt.case_sha256 {
                return Err(InventoryError::new(format!(
                    "executable case digest mismatch for {id}"
                )));
            }
            let executable = decode_executable_case(id.clone(), &raw)?;
            if executable.patterns.len() != receipt.pattern_count {
                return Err(InventoryError::new(format!(
                    "executable pattern count mismatch for {id}"
                )));
            }
            if cases.insert(id.clone(), executable).is_some() {
                return Err(InventoryError::new(format!(
                    "duplicate executable case {id}"
                )));
            }
        }
    }
    let expected_ids = inventory
        .payload
        .cases
        .iter()
        .filter(|case| case.corpus_membership == CorpusMembership::RustRegexSuite)
        .map(|case| case.id.as_str())
        .collect::<BTreeSet<_>>();
    let actual_ids = cases.keys().map(String::as_str).collect::<BTreeSet<_>>();
    if actual_ids != expected_ids {
        return Err(InventoryError::new(
            "executable case ID set differs from inventory",
        ));
    }
    Ok(cases)
}

/// Execute every obligation and authenticate the resulting report.
pub fn build_adapter_report(
    inventory: &Inventory,
    executable_cases: BTreeMap<String, ExecutableCase>,
    candidate: CandidateIdentity,
) -> Result<AdapterReport, InventoryError> {
    inventory.validate()?;
    validate_candidate(&candidate)?;
    let mut adapter = FreRegexAdapter::new(executable_cases)?;
    let receipts = run_adapter_scaffold(inventory, &mut adapter)?;
    let counts = AdapterDispositionCounts::from_receipts(&receipts)?;
    let payload = AdapterReportPayload {
        upstream_revision: UPSTREAM_REVISION.to_owned(),
        inventory_payload_sha256: inventory.payload_sha256.clone(),
        adapter_id: ADAPTER_ID.to_owned(),
        candidate,
        counts,
        receipts,
        limitations: LIMITATIONS
            .iter()
            .map(|value| (*value).to_owned())
            .collect(),
    };
    let payload_sha256 =
        sha256(&serde_json::to_vec(&payload).map_err(|error| {
            InventoryError::new(format!("encode adapter report payload: {error}"))
        })?);
    let report = AdapterReport {
        schema: ADAPTER_REPORT_SCHEMA.to_owned(),
        payload_sha256,
        payload,
    };
    report.validate(inventory)?;
    Ok(report)
}

/// Authenticate the exact clean source worktree used for the adapter run.
pub fn authenticate_candidate_source(path: &Path) -> Result<CandidateIdentity, InventoryError> {
    let metadata = fs::symlink_metadata(path).map_err(|error| {
        InventoryError::new(format!("stat candidate source {}: {error}", path.display()))
    })?;
    if metadata.file_type().is_symlink() || !metadata.file_type().is_dir() {
        return Err(InventoryError::new(
            "candidate source must be a real directory",
        ));
    }
    let compiled_root = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../..")
        .canonicalize()
        .map_err(|error| InventoryError::new(format!("canonicalize compiled root: {error}")))?;
    let requested_root = path
        .canonicalize()
        .map_err(|error| InventoryError::new(format!("canonicalize candidate source: {error}")))?;
    if requested_root != compiled_root {
        return Err(InventoryError::new(
            "candidate source is not the worktree that built this adapter",
        ));
    }
    let revision = git_output(path, &["rev-parse", "--verify", "HEAD^{commit}"])?;
    let tree = git_output(path, &["rev-parse", "--verify", "HEAD^{tree}"])?;
    let status = git_output(path, &["status", "--porcelain=v1", "--untracked-files=all"])?;
    if !status.is_empty() {
        return Err(InventoryError::new(format!(
            "candidate source is dirty: {status:?}"
        )));
    }
    let candidate = CandidateIdentity {
        revision,
        tree,
        tracked_and_untracked_worktree_clean: true,
    };
    validate_candidate(&candidate)?;
    Ok(candidate)
}

/// Read and authenticate a complete report against its exact inventory.
pub fn read_adapter_report(
    path: &Path,
    inventory: &Inventory,
) -> Result<AdapterReport, InventoryError> {
    let bytes = fs::read(path).map_err(|error| {
        InventoryError::new(format!("read adapter report {}: {error}", path.display()))
    })?;
    let report: AdapterReport = serde_json::from_slice(&bytes).map_err(|error| {
        InventoryError::new(format!("decode adapter report {}: {error}", path.display()))
    })?;
    report.validate(inventory)?;
    Ok(report)
}

/// Atomically write canonical pretty JSON for one authenticated report.
pub fn write_adapter_report(
    path: &Path,
    report: &AdapterReport,
    inventory: &Inventory,
) -> Result<(), InventoryError> {
    report.validate(inventory)?;
    let mut bytes = serde_json::to_vec_pretty(report)
        .map_err(|error| InventoryError::new(format!("encode adapter report: {error}")))?;
    bytes.push(b'\n');
    if let Ok(existing) = fs::read(path)
        && existing == bytes
    {
        return Ok(());
    }
    let parent = path.parent().ok_or_else(|| {
        InventoryError::new(format!(
            "adapter report output has no parent: {}",
            path.display()
        ))
    })?;
    let name = path
        .file_name()
        .and_then(|name| name.to_str())
        .ok_or_else(|| {
            InventoryError::new(format!("invalid adapter report name: {}", path.display()))
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

impl AdapterReport {
    /// Validate identity, payload hash, complete receipt order and counts.
    pub fn validate(&self, inventory: &Inventory) -> Result<(), InventoryError> {
        inventory.validate()?;
        if self.schema != ADAPTER_REPORT_SCHEMA {
            return Err(InventoryError::new("adapter report schema mismatch"));
        }
        let expected_hash = sha256(&serde_json::to_vec(&self.payload).map_err(|error| {
            InventoryError::new(format!("encode adapter report payload: {error}"))
        })?);
        if self.payload_sha256 != expected_hash {
            return Err(InventoryError::new(
                "adapter report payload SHA-256 mismatch",
            ));
        }
        if self.payload.upstream_revision != UPSTREAM_REVISION
            || self.payload.inventory_payload_sha256 != inventory.payload_sha256
            || self.payload.adapter_id != ADAPTER_ID
            || self.payload.limitations
                != LIMITATIONS
                    .iter()
                    .map(|value| (*value).to_owned())
                    .collect::<Vec<_>>()
        {
            return Err(InventoryError::new("adapter report identity mismatch"));
        }
        validate_candidate(&self.payload.candidate)?;
        if self.payload.receipts.len() != inventory.payload.scope.adapter_obligations {
            return Err(InventoryError::new("adapter report receipt count mismatch"));
        }
        let mut observed = 0_usize;
        for case in inventory
            .payload
            .cases
            .iter()
            .filter(|case| case.corpus_membership == CorpusMembership::RustRegexSuite)
        {
            for surface in AdapterSurface::ALL {
                let receipt = self.payload.receipts.get(observed).ok_or_else(|| {
                    InventoryError::new("adapter report ended before all obligations")
                })?;
                if receipt.case_id != case.id
                    || receipt.case_sha256 != case.case_sha256
                    || receipt.surface != surface
                {
                    return Err(InventoryError::new(format!(
                        "adapter report obligation order mismatch at {observed}"
                    )));
                }
                validate_disposition(&receipt.disposition)?;
                observed = observed
                    .checked_add(1)
                    .ok_or_else(|| InventoryError::new("adapter receipt index overflow"))?;
            }
        }
        let counts = AdapterDispositionCounts::from_receipts(&self.payload.receipts)?;
        if counts != self.payload.counts {
            return Err(InventoryError::new("adapter report count mismatch"));
        }
        Ok(())
    }
}

impl AdapterDispositionCounts {
    fn from_receipts(receipts: &[AdapterReceipt]) -> Result<Self, InventoryError> {
        let mut counts = Self::default();
        for receipt in receipts {
            let counter = match receipt.disposition {
                AdapterDisposition::Pass { .. } => &mut counts.pass,
                AdapterDisposition::Mismatch { .. } => &mut counts.mismatch,
                AdapterDisposition::Unsupported { .. } => &mut counts.unsupported,
                AdapterDisposition::NotApplicable { .. } => &mut counts.not_applicable,
                AdapterDisposition::Fault { .. } => &mut counts.fault,
            };
            *counter = counter
                .checked_add(1)
                .ok_or_else(|| InventoryError::new("adapter disposition count overflow"))?;
            counts.total = counts
                .total
                .checked_add(1)
                .ok_or_else(|| InventoryError::new("adapter total count overflow"))?;
        }
        Ok(counts)
    }
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "kebab-case", tag = "kind", content = "value")]
enum SemanticValue {
    CompileAccepted(bool),
    IsMatch(bool),
    Matches(Vec<ExpectedSpan>),
    Captures(Vec<ExpectedCaptures>),
    PatternIds(Vec<usize>),
}

enum BuildAttempt {
    Built(Box<PortableRegex>),
    Rejected,
    Unsupported(AdapterDisposition),
    Fault(AdapterDisposition),
}

enum TextBuildAttempt {
    Built(Box<PortableTextRegex>),
    Rejected,
    Unsupported(AdapterDisposition),
    Fault(AdapterDisposition),
}

enum TextSetBuildAttempt {
    Built(Box<PortableTextRegexSet>),
    Rejected,
    Unsupported(AdapterDisposition),
    Fault(AdapterDisposition),
}

enum BytesSetBuildAttempt {
    Built(Box<PortableRegexSet>),
    Rejected,
    Unsupported(AdapterDisposition),
    Fault(AdapterDisposition),
}

enum CaptureBuildAttempt {
    Built(Box<CaptureRegex>),
    Rejected,
    Unsupported(AdapterDisposition),
    Fault(AdapterDisposition),
}

enum TextCaptureBuildAttempt {
    Built(Box<PortableTextCaptureRegex>),
    Rejected,
    Unsupported(AdapterDisposition),
    Fault(AdapterDisposition),
}

fn execute_text_compile(case: &CaseReceipt, input: &ExecutableCase) -> AdapterDisposition {
    let expected = SemanticValue::CompileAccepted(case.compiles);
    match build_text(case, input) {
        TextBuildAttempt::Built(_) => compare(&expected, &SemanticValue::CompileAccepted(true)),
        TextBuildAttempt::Rejected => compare(&expected, &SemanticValue::CompileAccepted(false)),
        TextBuildAttempt::Unsupported(disposition) | TextBuildAttempt::Fault(disposition) => {
            disposition
        }
    }
}

fn execute_text_is_match(case: &CaseReceipt, input: &ExecutableCase) -> AdapterDisposition {
    let expected = SemanticValue::IsMatch(!input.expected.is_empty());
    let regex = match build_text(case, input) {
        TextBuildAttempt::Built(regex) => regex,
        TextBuildAttempt::Rejected => {
            return mismatch(
                &expected,
                &SemanticValue::CompileAccepted(false),
                "compile.unexpected-rejection",
            );
        }
        TextBuildAttempt::Unsupported(disposition) | TextBuildAttempt::Fault(disposition) => {
            return disposition;
        }
    };
    let Ok(haystack) = std::str::from_utf8(&input.haystack) else {
        return fault("adapter.text-haystack-invalid-utf8");
    };
    let Some(bounds) = text_search_bounds(haystack, input.bounds) else {
        return compare(&expected, &SemanticValue::IsMatch(false));
    };
    match regex.find_window(
        haystack,
        SearchWindow::new(bounds.start, bounds.end),
        SearchLimits::unlimited(),
    ) {
        Ok((observed, _)) => {
            let observed = observed
                .is_some_and(|matched| !case.anchored || matched.start() == input.bounds.start);
            compare(&expected, &SemanticValue::IsMatch(observed))
        }
        Err(_) => unsupported(
            CapabilityId::RustTextFacade,
            "search.portable-execution-refused",
        ),
    }
}

fn execute_text_find(case: &CaseReceipt, input: &ExecutableCase) -> AdapterDisposition {
    let Ok(expected_spans) = expected_spans(input) else {
        return fault("adapter.expected-group-zero-missing");
    };
    let expected = SemanticValue::Matches(expected_spans);
    if case.search_kind == SearchKind::Overlapping {
        return execute_text_overlapping(case, input, &expected, true);
    }
    if case.search_kind == SearchKind::Earliest || case.match_kind == MatchKind::All {
        return execute_text_capture_find(case, input, &expected);
    }
    let regex = match build_text(case, input) {
        TextBuildAttempt::Built(regex) => regex,
        TextBuildAttempt::Rejected => {
            return mismatch(
                &expected,
                &SemanticValue::CompileAccepted(false),
                "compile.unexpected-rejection",
            );
        }
        TextBuildAttempt::Unsupported(disposition) | TextBuildAttempt::Fault(disposition) => {
            return disposition;
        }
    };
    let Ok(haystack) = std::str::from_utf8(&input.haystack) else {
        return fault("adapter.text-haystack-invalid-utf8");
    };
    match collect_text_matches(
        &regex,
        haystack,
        input.bounds,
        case.match_limit,
        case.anchored,
    ) {
        Ok(observed) => compare(&expected, &SemanticValue::Matches(observed)),
        Err(_) => unsupported(
            CapabilityId::RustTextFacade,
            "search.portable-execution-refused",
        ),
    }
}

fn execute_text_capture_find(
    case: &CaseReceipt,
    input: &ExecutableCase,
    expected: &SemanticValue,
) -> AdapterDisposition {
    let regex = match build_text_captures(case, input) {
        TextCaptureBuildAttempt::Built(regex) => regex,
        TextCaptureBuildAttempt::Rejected => {
            return mismatch(
                expected,
                &SemanticValue::CompileAccepted(false),
                "compile.unexpected-rejection",
            );
        }
        TextCaptureBuildAttempt::Unsupported(disposition)
        | TextCaptureBuildAttempt::Fault(disposition) => return disposition,
    };
    let Ok(haystack) = std::str::from_utf8(&input.haystack) else {
        return fault("adapter.text-haystack-invalid-utf8");
    };
    let Some(bounds) = text_search_bounds(haystack, input.bounds) else {
        return compare(expected, &SemanticValue::Matches(Vec::new()));
    };
    let config = match capture_search_config(case) {
        Ok(config) => config,
        Err(disposition) => return disposition,
    };
    let Ok(report) = regex.captures_iter_window_with_config(
        haystack,
        CaptureWindow {
            start: bounds.start,
            end: bounds.end,
        },
        config,
        CaptureAggregateLimits::default(),
    ) else {
        return unsupported(
            CapabilityId::CaptureIteration,
            "search.text-configured-execution-refused",
        );
    };
    let Ok(mut observed) = capture_records(&report.captures, input.haystack.len()) else {
        return fault("adapter.text-earliest-record-invariant");
    };
    if case.anchored {
        let Ok(filtered) = anchored_capture_prefix(observed, input.bounds, Some(haystack)) else {
            return fault("adapter.text-earliest-anchored-invariant");
        };
        observed = filtered;
    }
    let Ok(mut spans) = group_zero_spans(&observed) else {
        return fault("adapter.text-earliest-group-zero-invariant");
    };
    if let Some(limit) = case.match_limit {
        spans.truncate(limit);
    }
    compare(expected, &SemanticValue::Matches(spans))
}

fn build_text(case: &CaseReceipt, input: &ExecutableCase) -> TextBuildAttempt {
    let Some(pattern) = input.patterns.first() else {
        return TextBuildAttempt::Fault(fault("adapter.single-pattern-missing"));
    };
    build_text_pattern(case, input, pattern)
}

fn build_text_pattern(
    case: &CaseReceipt,
    input: &ExecutableCase,
    pattern: &str,
) -> TextBuildAttempt {
    let mut profile = RustProfile::default();
    profile.options.case_insensitive = case.case_insensitive;
    profile.options.unicode = case.unicode;
    profile.options.line_terminator = input.line_terminator;
    match PortableTextBuilder::new(pattern.to_owned())
        .profile(profile)
        .build()
    {
        Ok(regex) => TextBuildAttempt::Built(Box::new(regex)),
        Err(PortableTextBuildError::TextSyntax(error))
            if matches!(&error.category, ErrorCategory::UpstreamRustSyntax) =>
        {
            TextBuildAttempt::Rejected
        }
        Err(
            PortableTextBuildError::InternalInvariant(_)
            | PortableTextBuildError::FiniteProof(
                BuildError::AllocationFailed { .. } | BuildError::InternalInvariant(_),
            )
            | PortableTextBuildError::EquivalenceProof(
                BuildError::AllocationFailed { .. } | BuildError::InternalInvariant(_),
            )
            | PortableTextBuildError::Portable(
                BuildError::AllocationFailed { .. } | BuildError::InternalInvariant(_),
            ),
        ) => TextBuildAttempt::Fault(fault("build.text-internal-fault")),
        Err(PortableTextBuildError::TextSyntax(error))
            if matches!(
                &error.category,
                ErrorCategory::FreResourceLimit { .. }
                    | ErrorCategory::StrictQualificationFailure { .. }
            ) =>
        {
            TextBuildAttempt::Unsupported(unsupported(
                CapabilityId::RustTextFacade,
                "build.syntax-resource-envelope",
            ))
        }
        Err(PortableTextBuildError::NonFiniteLanguage) => {
            TextBuildAttempt::Unsupported(unsupported(
                CapabilityId::RustTextFacade,
                "build.text-equivalence-proof-gap",
            ))
        }
        Err(
            PortableTextBuildError::BytesProofSyntax(_)
            | PortableTextBuildError::ProfileLanguageMismatch
            | PortableTextBuildError::InvalidUtf8Word,
        ) => TextBuildAttempt::Unsupported(unsupported(
            CapabilityId::RustTextFacade,
            "build.text-bytes-equivalence-gap",
        )),
        Err(
            PortableTextBuildError::FiniteProof(_)
            | PortableTextBuildError::EquivalenceProof(_)
            | PortableTextBuildError::Portable(_),
        ) => TextBuildAttempt::Unsupported(unsupported(
            CapabilityId::RustTextFacade,
            "build.portable-subset-gap",
        )),
        Err(PortableTextBuildError::TextSyntax(_)) => {
            TextBuildAttempt::Fault(fault("build.text-syntax-unexpected-error"))
        }
        Err(_) => TextBuildAttempt::Fault(fault("build.text-unclassified-error")),
    }
}

fn execute_text_set_compile(case: &CaseReceipt, input: &ExecutableCase) -> AdapterDisposition {
    let expected = SemanticValue::CompileAccepted(case.compiles);
    match build_text_set(case, input) {
        TextSetBuildAttempt::Built(_) => compare(&expected, &SemanticValue::CompileAccepted(true)),
        TextSetBuildAttempt::Rejected => compare(&expected, &SemanticValue::CompileAccepted(false)),
        TextSetBuildAttempt::Unsupported(disposition) | TextSetBuildAttempt::Fault(disposition) => {
            disposition
        }
    }
}

fn singleton_set_expected(
    surface: AdapterSurface,
    input: &ExecutableCase,
) -> Result<SemanticValue, AdapterDisposition> {
    if input.patterns.len() != 1 {
        return Err(fault("adapter.singleton-set-pattern-count"));
    }
    match surface {
        AdapterSurface::RustTextSetIsMatch | AdapterSurface::RustBytesSetIsMatch => {
            Ok(SemanticValue::IsMatch(!input.expected.is_empty()))
        }
        AdapterSurface::RustTextSetWhich | AdapterSurface::RustBytesSetWhich => {
            let ids = expected_pattern_ids(input);
            if ids.iter().any(|&id| id != 0) {
                return Err(fault("adapter.singleton-set-pattern-id"));
            }
            Ok(SemanticValue::PatternIds(ids))
        }
        _ => Err(fault("adapter.singleton-set-surface")),
    }
}

fn singleton_set_observed(surface: AdapterSurface, matched: bool) -> SemanticValue {
    match surface {
        AdapterSurface::RustTextSetIsMatch | AdapterSurface::RustBytesSetIsMatch => {
            SemanticValue::IsMatch(matched)
        }
        AdapterSurface::RustTextSetWhich | AdapterSurface::RustBytesSetWhich => {
            SemanticValue::PatternIds(if matched { vec![0] } else { Vec::new() })
        }
        _ => unreachable!("singleton set helper receives only observation surfaces"),
    }
}

/// Prove native text-set compilation, then delegate its singleton observation
/// to the already-qualified single-pattern text facade. The delegation is
/// needed when anchoring or bounded search is not exposed by the native set.
fn execute_text_singleton_set_observation(
    surface: AdapterSurface,
    case: &CaseReceipt,
    input: &ExecutableCase,
) -> AdapterDisposition {
    let expected = match singleton_set_expected(surface, input) {
        Ok(expected) => expected,
        Err(disposition) => return disposition,
    };
    match build_text_set(case, input) {
        TextSetBuildAttempt::Built(_) => {}
        TextSetBuildAttempt::Rejected => {
            return mismatch(
                &expected,
                &SemanticValue::CompileAccepted(false),
                "compile.unexpected-rejection",
            );
        }
        TextSetBuildAttempt::Unsupported(disposition) | TextSetBuildAttempt::Fault(disposition) => {
            return disposition;
        }
    }
    let regex = match build_text(case, input) {
        TextBuildAttempt::Built(regex) => regex,
        TextBuildAttempt::Rejected => {
            return mismatch(
                &expected,
                &SemanticValue::CompileAccepted(false),
                "compile.unexpected-rejection",
            );
        }
        TextBuildAttempt::Unsupported(disposition) | TextBuildAttempt::Fault(disposition) => {
            return disposition;
        }
    };
    let Ok(haystack) = std::str::from_utf8(&input.haystack) else {
        return fault("adapter.text-haystack-invalid-utf8");
    };
    let Some(bounds) = text_search_bounds(haystack, input.bounds) else {
        return compare(&expected, &singleton_set_observed(surface, false));
    };
    match regex.find_window(
        haystack,
        SearchWindow::new(bounds.start, bounds.end),
        SearchLimits::unlimited(),
    ) {
        Ok((observed, _)) => {
            let matched = observed
                .is_some_and(|matched| !case.anchored || matched.start() == input.bounds.start);
            compare(&expected, &singleton_set_observed(surface, matched))
        }
        Err(_) => unsupported(
            CapabilityId::RustTextSetFacade,
            "search.text-singleton-set-delegate-refused",
        ),
    }
}

/// Prove native bytes-set compilation, then delegate its singleton observation
/// to the already-qualified single-pattern bytes facade.
fn execute_bytes_singleton_set_observation(
    surface: AdapterSurface,
    case: &CaseReceipt,
    input: &ExecutableCase,
) -> AdapterDisposition {
    let expected = match singleton_set_expected(surface, input) {
        Ok(expected) => expected,
        Err(disposition) => return disposition,
    };
    match build_bytes_set(case, input) {
        BytesSetBuildAttempt::Built(_) => {}
        BytesSetBuildAttempt::Rejected => {
            return mismatch(
                &expected,
                &SemanticValue::CompileAccepted(false),
                "compile.unexpected-rejection",
            );
        }
        BytesSetBuildAttempt::Unsupported(disposition)
        | BytesSetBuildAttempt::Fault(disposition) => return disposition,
    }
    let regex = match build_bytes(case, input) {
        BuildAttempt::Built(regex) => regex,
        BuildAttempt::Rejected => {
            return mismatch(
                &expected,
                &SemanticValue::CompileAccepted(false),
                "compile.unexpected-rejection",
            );
        }
        BuildAttempt::Unsupported(disposition) | BuildAttempt::Fault(disposition) => {
            return disposition;
        }
    };
    match regex.find_window(
        &input.haystack,
        SearchWindow::new(input.bounds.start, input.bounds.end),
        SearchLimits::unlimited(),
    ) {
        Ok((observed, _)) => {
            let matched = observed
                .is_some_and(|matched| !case.anchored || matched.start() == input.bounds.start);
            compare(&expected, &singleton_set_observed(surface, matched))
        }
        Err(_) => unsupported(
            CapabilityId::RustBytesSetFacade,
            "search.bytes-singleton-set-delegate-refused",
        ),
    }
}

fn execute_text_set_is_match(case: &CaseReceipt, input: &ExecutableCase) -> AdapterDisposition {
    let expected = SemanticValue::IsMatch(!input.expected.is_empty());
    let set = match build_text_set(case, input) {
        TextSetBuildAttempt::Built(set) => set,
        TextSetBuildAttempt::Rejected => {
            return mismatch(
                &expected,
                &SemanticValue::CompileAccepted(false),
                "compile.unexpected-rejection",
            );
        }
        TextSetBuildAttempt::Unsupported(disposition) | TextSetBuildAttempt::Fault(disposition) => {
            return disposition;
        }
    };
    let Ok(haystack) = std::str::from_utf8(&input.haystack) else {
        return fault("adapter.text-haystack-invalid-utf8");
    };
    match set.is_match(haystack, PortableRegexSetRunLimits::unlimited()) {
        Ok((observed, _)) => compare(&expected, &SemanticValue::IsMatch(observed)),
        Err(_) => unsupported(
            CapabilityId::RustTextSetFacade,
            "search.text-set-execution-refused",
        ),
    }
}

fn execute_text_set_which(case: &CaseReceipt, input: &ExecutableCase) -> AdapterDisposition {
    let expected = SemanticValue::PatternIds(expected_pattern_ids(input));
    let set = match build_text_set(case, input) {
        TextSetBuildAttempt::Built(set) => set,
        TextSetBuildAttempt::Rejected => {
            return mismatch(
                &expected,
                &SemanticValue::CompileAccepted(false),
                "compile.unexpected-rejection",
            );
        }
        TextSetBuildAttempt::Unsupported(disposition) | TextSetBuildAttempt::Fault(disposition) => {
            return disposition;
        }
    };
    let Ok(haystack) = std::str::from_utf8(&input.haystack) else {
        return fault("adapter.text-haystack-invalid-utf8");
    };
    match set.matches(haystack, PortableRegexSetRunLimits::unlimited()) {
        Ok(observed) => compare(
            &expected,
            &SemanticValue::PatternIds(observed.iter().collect()),
        ),
        Err(_) => unsupported(
            CapabilityId::RustTextSetFacade,
            "search.text-set-execution-refused",
        ),
    }
}

/// Execute the selection-sensitive ordered-union modes that ordinary
/// `RegexSet` membership deliberately does not expose. This first proves the
/// complete set constructor, then builds the same patterns independently and
/// selects winners using only FRE match spans and declaration order.
fn execute_text_selected_set_which(
    case: &CaseReceipt,
    input: &ExecutableCase,
) -> AdapterDisposition {
    let expected = SemanticValue::PatternIds(expected_pattern_ids(input));
    match build_text_set(case, input) {
        TextSetBuildAttempt::Built(_) => {}
        TextSetBuildAttempt::Rejected => {
            return mismatch(
                &expected,
                &SemanticValue::CompileAccepted(false),
                "compile.unexpected-rejection",
            );
        }
        TextSetBuildAttempt::Unsupported(disposition) | TextSetBuildAttempt::Fault(disposition) => {
            return disposition;
        }
    }
    let Ok(haystack) = std::str::from_utf8(&input.haystack) else {
        return fault("adapter.text-haystack-invalid-utf8");
    };
    let mut regexes = Vec::new();
    if regexes.try_reserve_exact(input.patterns.len()).is_err() {
        return fault("adapter.text-selected-set-allocation-failed");
    }
    for pattern in &input.patterns {
        match build_text_pattern(case, input, pattern) {
            TextBuildAttempt::Built(regex) => regexes.push(regex),
            TextBuildAttempt::Rejected => {
                return mismatch(
                    &expected,
                    &SemanticValue::CompileAccepted(false),
                    "compile.unexpected-rejection",
                );
            }
            TextBuildAttempt::Unsupported(disposition) | TextBuildAttempt::Fault(disposition) => {
                return disposition;
            }
        }
    }
    let observed =
        match selected_text_pattern_ids(&regexes, haystack, case.search_kind, case.match_kind) {
            Ok(observed) => observed,
            Err(SelectedSetError::UnsupportedPlan) => {
                return unsupported(
                    CapabilityId::RustTextSetFacade,
                    "search.text-set-selection-plan-gap",
                );
            }
            Err(SelectedSetError::Search) => {
                return unsupported(
                    CapabilityId::RustTextSetFacade,
                    "search.text-set-selection-refused",
                );
            }
        };
    compare(&expected, &SemanticValue::PatternIds(observed))
}

fn execute_bytes_selected_set_which(
    case: &CaseReceipt,
    input: &ExecutableCase,
) -> AdapterDisposition {
    let expected = SemanticValue::PatternIds(expected_pattern_ids(input));
    match build_bytes_set(case, input) {
        BytesSetBuildAttempt::Built(_) => {}
        BytesSetBuildAttempt::Rejected => {
            return mismatch(
                &expected,
                &SemanticValue::CompileAccepted(false),
                "compile.unexpected-rejection",
            );
        }
        BytesSetBuildAttempt::Unsupported(disposition)
        | BytesSetBuildAttempt::Fault(disposition) => return disposition,
    }
    let mut regexes = Vec::new();
    if regexes.try_reserve_exact(input.patterns.len()).is_err() {
        return fault("adapter.bytes-selected-set-allocation-failed");
    }
    for pattern in &input.patterns {
        match build_bytes_pattern(case, input, pattern) {
            BuildAttempt::Built(regex) => regexes.push(regex),
            BuildAttempt::Rejected => {
                return mismatch(
                    &expected,
                    &SemanticValue::CompileAccepted(false),
                    "compile.unexpected-rejection",
                );
            }
            BuildAttempt::Unsupported(disposition) | BuildAttempt::Fault(disposition) => {
                return disposition;
            }
        }
    }
    let observed = match selected_byte_pattern_ids(
        &regexes,
        &input.haystack,
        case.search_kind,
        case.match_kind,
    ) {
        Ok(observed) => observed,
        Err(SelectedSetError::UnsupportedPlan) => {
            return unsupported(
                CapabilityId::RustBytesSetFacade,
                "search.bytes-set-selection-plan-gap",
            );
        }
        Err(SelectedSetError::Search) => {
            return unsupported(
                CapabilityId::RustBytesSetFacade,
                "search.bytes-set-selection-refused",
            );
        }
    };
    compare(&expected, &SemanticValue::PatternIds(observed))
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum SelectedSetError {
    UnsupportedPlan,
    Search,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct SelectedPatternMatch {
    id: usize,
    start: usize,
    end: usize,
}

/// Adapter-only correctness fallback for selection-sensitive set observations.
/// With `P` patterns and `H` searchable positions, the implementation can
/// issue `O(P * H)` independent constituent facade searches, each over a
/// remaining haystack window. It deliberately makes no native `RegexSet` or
/// production-throughput claim.
fn selected_text_pattern_ids(
    regexes: &[Box<PortableTextRegex>],
    haystack: &str,
    search_kind: SearchKind,
    match_kind: MatchKind,
) -> Result<Vec<usize>, SelectedSetError> {
    match (search_kind, match_kind) {
        (SearchKind::Leftmost, MatchKind::LeftmostFirst) => {
            selected_text_leftmost_first(regexes, haystack, true)
        }
        (SearchKind::Overlapping, MatchKind::LeftmostFirst) => {
            selected_text_leftmost_first(regexes, haystack, false)
        }
        (SearchKind::Leftmost, MatchKind::All) => selected_text_last_literal(regexes, haystack),
        _ => Err(SelectedSetError::UnsupportedPlan),
    }
}

fn selected_byte_pattern_ids(
    regexes: &[Box<PortableRegex>],
    haystack: &[u8],
    search_kind: SearchKind,
    match_kind: MatchKind,
) -> Result<Vec<usize>, SelectedSetError> {
    match (search_kind, match_kind) {
        (SearchKind::Leftmost, MatchKind::LeftmostFirst) => {
            selected_bytes_leftmost_first(regexes, haystack, true)
        }
        (SearchKind::Overlapping, MatchKind::LeftmostFirst) => {
            selected_bytes_leftmost_first(regexes, haystack, false)
        }
        (SearchKind::Leftmost, MatchKind::All) => selected_bytes_last_literal(regexes, haystack),
        _ => Err(SelectedSetError::UnsupportedPlan),
    }
}

fn selected_text_leftmost_first(
    regexes: &[Box<PortableTextRegex>],
    haystack: &str,
    iterate: bool,
) -> Result<Vec<usize>, SelectedSetError> {
    let mut selected = BTreeSet::new();
    let mut start = 0_usize;
    let mut last_match_end = None;
    loop {
        let Some(matched) = text_leftmost_first_at(regexes, haystack, start)? else {
            break;
        };
        if matched.start == matched.end && last_match_end == Some(matched.end) {
            let Some(next) = advance_text_scalar(haystack, start) else {
                break;
            };
            start = next;
            continue;
        }
        selected.insert(matched.id);
        if !iterate || selected.len() == regexes.len() {
            break;
        }
        start = matched.end;
        last_match_end = Some(matched.end);
    }
    Ok(selected.into_iter().collect())
}

fn selected_bytes_leftmost_first(
    regexes: &[Box<PortableRegex>],
    haystack: &[u8],
    iterate: bool,
) -> Result<Vec<usize>, SelectedSetError> {
    let mut selected = BTreeSet::new();
    let mut start = 0_usize;
    let mut last_match_end = None;
    loop {
        let Some(matched) = bytes_leftmost_first_at(regexes, haystack, start)? else {
            break;
        };
        if matched.start == matched.end && last_match_end == Some(matched.end) {
            if start == haystack.len() {
                break;
            }
            start = start.checked_add(1).ok_or(SelectedSetError::Search)?;
            continue;
        }
        selected.insert(matched.id);
        if !iterate || selected.len() == regexes.len() {
            break;
        }
        start = matched.end;
        last_match_end = Some(matched.end);
    }
    Ok(selected.into_iter().collect())
}

fn text_leftmost_first_at(
    regexes: &[Box<PortableTextRegex>],
    haystack: &str,
    start: usize,
) -> Result<Option<SelectedPatternMatch>, SelectedSetError> {
    let mut winner: Option<SelectedPatternMatch> = None;
    for (id, regex) in regexes.iter().enumerate() {
        let (matched, _) = regex
            .find_window(
                haystack,
                SearchWindow::new(start, haystack.len()),
                SearchLimits::unlimited(),
            )
            .map_err(|_| SelectedSetError::Search)?;
        let Some(matched) = matched else { continue };
        let candidate = SelectedPatternMatch {
            id,
            start: matched.start(),
            end: matched.end(),
        };
        if winner
            .is_none_or(|current| (candidate.start, candidate.id) < (current.start, current.id))
        {
            winner = Some(candidate);
        }
    }
    Ok(winner)
}

fn bytes_leftmost_first_at(
    regexes: &[Box<PortableRegex>],
    haystack: &[u8],
    start: usize,
) -> Result<Option<SelectedPatternMatch>, SelectedSetError> {
    let mut winner: Option<SelectedPatternMatch> = None;
    for (id, regex) in regexes.iter().enumerate() {
        let (matched, _) = regex
            .find_window(
                haystack,
                SearchWindow::new(start, haystack.len()),
                SearchLimits::unlimited(),
            )
            .map_err(|_| SelectedSetError::Search)?;
        let Some(matched) = matched else { continue };
        let candidate = SelectedPatternMatch {
            id,
            start: matched.start(),
            end: matched.end(),
        };
        if winner
            .is_none_or(|current| (candidate.start, candidate.id) < (current.start, current.id))
        {
            winner = Some(candidate);
        }
    }
    Ok(winner)
}

fn selected_text_last_literal(
    regexes: &[Box<PortableTextRegex>],
    haystack: &str,
) -> Result<Vec<usize>, SelectedSetError> {
    if regexes
        .iter()
        .any(|regex| regex.build_report().portable.plan != PlanKind::ExactLiteral)
    {
        return Err(SelectedSetError::UnsupportedPlan);
    }
    let mut winner = None;
    for (id, regex) in regexes.iter().enumerate() {
        let mut start = 0_usize;
        loop {
            let (matched, _) = regex
                .find_window(
                    haystack,
                    SearchWindow::new(start, haystack.len()),
                    SearchLimits::unlimited(),
                )
                .map_err(|_| SelectedSetError::Search)?;
            let Some(matched) = matched else { break };
            let candidate = SelectedPatternMatch {
                id,
                start: matched.start(),
                end: matched.end(),
            };
            if winner.is_none_or(|current| last_literal_candidate_wins(candidate, current)) {
                winner = Some(candidate);
            }
            let Some(next) = advance_text_scalar(haystack, matched.start()) else {
                break;
            };
            start = next;
        }
    }
    Ok(winner.into_iter().map(|matched| matched.id).collect())
}

fn selected_bytes_last_literal(
    regexes: &[Box<PortableRegex>],
    haystack: &[u8],
) -> Result<Vec<usize>, SelectedSetError> {
    if regexes
        .iter()
        .any(|regex| regex.build_report().plan != PlanKind::ExactLiteral)
    {
        return Err(SelectedSetError::UnsupportedPlan);
    }
    let mut winner = None;
    for (id, regex) in regexes.iter().enumerate() {
        let mut start = 0_usize;
        loop {
            let (matched, _) = regex
                .find_window(
                    haystack,
                    SearchWindow::new(start, haystack.len()),
                    SearchLimits::unlimited(),
                )
                .map_err(|_| SelectedSetError::Search)?;
            let Some(matched) = matched else { break };
            let candidate = SelectedPatternMatch {
                id,
                start: matched.start(),
                end: matched.end(),
            };
            if winner.is_none_or(|current| last_literal_candidate_wins(candidate, current)) {
                winner = Some(candidate);
            }
            if matched.start() == haystack.len() {
                break;
            }
            start = matched
                .start()
                .checked_add(1)
                .ok_or(SelectedSetError::Search)?;
        }
    }
    Ok(winner.into_iter().map(|matched| matched.id).collect())
}

fn last_literal_candidate_wins(
    candidate: SelectedPatternMatch,
    current: SelectedPatternMatch,
) -> bool {
    candidate.end > current.end || (candidate.end == current.end && candidate.id < current.id)
}

fn advance_text_scalar(haystack: &str, start: usize) -> Option<usize> {
    if start == haystack.len() {
        return None;
    }
    haystack[start..]
        .chars()
        .next()
        .map(|scalar| start.saturating_add(scalar.len_utf8()))
}

fn expected_pattern_ids(input: &ExecutableCase) -> Vec<usize> {
    input
        .expected
        .iter()
        .map(|matched| matched.pattern_id)
        .collect::<BTreeSet<_>>()
        .into_iter()
        .collect()
}

fn build_text_set(case: &CaseReceipt, input: &ExecutableCase) -> TextSetBuildAttempt {
    let mut profile = RustProfile::default();
    profile.options.case_insensitive = case.case_insensitive;
    profile.options.unicode = case.unicode;
    profile.options.line_terminator = input.line_terminator;
    match PortableTextRegexSetBuilder::new(&input.patterns)
        .profile(profile)
        .build()
    {
        Ok(set) => TextSetBuildAttempt::Built(Box::new(set)),
        Err(PortableTextRegexSetBuildError::Pattern {
            source: PortableTextBuildError::TextSyntax(error),
            ..
        }) if matches!(&error.category, ErrorCategory::UpstreamRustSyntax) => {
            TextSetBuildAttempt::Rejected
        }
        Err(PortableTextRegexSetBuildError::Pattern {
            source:
                PortableTextBuildError::InternalInvariant(_)
                | PortableTextBuildError::FiniteProof(
                    BuildError::AllocationFailed { .. } | BuildError::InternalInvariant(_),
                )
                | PortableTextBuildError::EquivalenceProof(
                    BuildError::AllocationFailed { .. } | BuildError::InternalInvariant(_),
                )
                | PortableTextBuildError::Portable(
                    BuildError::AllocationFailed { .. } | BuildError::InternalInvariant(_),
                ),
            ..
        }) => TextSetBuildAttempt::Fault(fault("build.text-set-pattern-internal-fault")),
        Err(PortableTextRegexSetBuildError::Pattern {
            source: PortableTextBuildError::TextSyntax(error),
            ..
        }) if matches!(
            &error.category,
            ErrorCategory::FreResourceLimit { .. }
                | ErrorCategory::StrictQualificationFailure { .. }
        ) =>
        {
            TextSetBuildAttempt::Unsupported(unsupported(
                CapabilityId::RustTextSetFacade,
                "build.text-set-syntax-resource-envelope",
            ))
        }
        Err(PortableTextRegexSetBuildError::Pattern {
            source: PortableTextBuildError::NonFiniteLanguage,
            ..
        }) => TextSetBuildAttempt::Unsupported(unsupported(
            CapabilityId::RustTextSetFacade,
            "build.text-set-equivalence-proof-gap",
        )),
        Err(PortableTextRegexSetBuildError::Pattern {
            source:
                PortableTextBuildError::BytesProofSyntax(_)
                | PortableTextBuildError::ProfileLanguageMismatch
                | PortableTextBuildError::InvalidUtf8Word,
            ..
        }) => TextSetBuildAttempt::Unsupported(unsupported(
            CapabilityId::RustTextSetFacade,
            "build.text-set-bytes-equivalence-gap",
        )),
        Err(PortableTextRegexSetBuildError::Pattern {
            source:
                PortableTextBuildError::FiniteProof(_)
                | PortableTextBuildError::EquivalenceProof(_)
                | PortableTextBuildError::Portable(_),
            ..
        }) => TextSetBuildAttempt::Unsupported(unsupported(
            CapabilityId::RustTextSetFacade,
            "build.text-set-portable-subset-gap",
        )),
        Err(PortableTextRegexSetBuildError::Pattern {
            source: PortableTextBuildError::TextSyntax(_),
            ..
        }) => TextSetBuildAttempt::Fault(fault("build.text-set-syntax-unexpected-error")),
        Err(
            PortableTextRegexSetBuildError::PatternLimit { .. }
            | PortableTextRegexSetBuildError::PatternBytesLimit { .. }
            | PortableTextRegexSetBuildError::PersistentLimit { .. },
        ) => TextSetBuildAttempt::Unsupported(unsupported(
            CapabilityId::RustTextSetFacade,
            "build.text-set-resource-envelope",
        )),
        Err(
            PortableTextRegexSetBuildError::AllocationFailed { .. }
            | PortableTextRegexSetBuildError::ArithmeticOverflow { .. },
        ) => TextSetBuildAttempt::Fault(fault("build.text-set-internal-fault")),
        Err(_) => TextSetBuildAttempt::Fault(fault("build.text-set-unclassified-error")),
    }
}

fn execute_bytes_set_compile(case: &CaseReceipt, input: &ExecutableCase) -> AdapterDisposition {
    let expected = SemanticValue::CompileAccepted(case.compiles);
    match build_bytes_set(case, input) {
        BytesSetBuildAttempt::Built(_) => compare(&expected, &SemanticValue::CompileAccepted(true)),
        BytesSetBuildAttempt::Rejected => {
            compare(&expected, &SemanticValue::CompileAccepted(false))
        }
        BytesSetBuildAttempt::Unsupported(disposition)
        | BytesSetBuildAttempt::Fault(disposition) => disposition,
    }
}

fn execute_bytes_set_is_match(case: &CaseReceipt, input: &ExecutableCase) -> AdapterDisposition {
    let expected = SemanticValue::IsMatch(!input.expected.is_empty());
    let set = match build_bytes_set(case, input) {
        BytesSetBuildAttempt::Built(set) => set,
        BytesSetBuildAttempt::Rejected => {
            return mismatch(
                &expected,
                &SemanticValue::CompileAccepted(false),
                "compile.unexpected-rejection",
            );
        }
        BytesSetBuildAttempt::Unsupported(disposition)
        | BytesSetBuildAttempt::Fault(disposition) => return disposition,
    };
    match set.is_match(&input.haystack, PortableRegexSetRunLimits::unlimited()) {
        Ok((observed, _)) => compare(&expected, &SemanticValue::IsMatch(observed)),
        Err(_) => unsupported(
            CapabilityId::RustBytesSetFacade,
            "search.bytes-set-execution-refused",
        ),
    }
}

fn execute_bytes_set_which(case: &CaseReceipt, input: &ExecutableCase) -> AdapterDisposition {
    let expected = SemanticValue::PatternIds(expected_pattern_ids(input));
    let set = match build_bytes_set(case, input) {
        BytesSetBuildAttempt::Built(set) => set,
        BytesSetBuildAttempt::Rejected => {
            return mismatch(
                &expected,
                &SemanticValue::CompileAccepted(false),
                "compile.unexpected-rejection",
            );
        }
        BytesSetBuildAttempt::Unsupported(disposition)
        | BytesSetBuildAttempt::Fault(disposition) => return disposition,
    };
    match set.matches(&input.haystack, PortableRegexSetRunLimits::unlimited()) {
        Ok(observed) => compare(
            &expected,
            &SemanticValue::PatternIds(observed.iter().collect()),
        ),
        Err(_) => unsupported(
            CapabilityId::RustBytesSetFacade,
            "search.bytes-set-execution-refused",
        ),
    }
}

fn build_bytes_set(case: &CaseReceipt, input: &ExecutableCase) -> BytesSetBuildAttempt {
    let mut profile = RustProfile::default();
    profile.options.case_insensitive = case.case_insensitive;
    profile.options.unicode = case.unicode;
    profile.options.line_terminator = input.line_terminator;
    match PortableRegexSetBuilder::new(&input.patterns)
        .profile(profile)
        .build()
    {
        Ok(set) => BytesSetBuildAttempt::Built(Box::new(set)),
        Err(PortableRegexSetBuildError::Pattern {
            source: BuildError::Syntax(error),
            ..
        }) if matches!(&error.category, ErrorCategory::UpstreamRustSyntax) => {
            BytesSetBuildAttempt::Rejected
        }
        Err(PortableRegexSetBuildError::Pattern {
            source: BuildError::AllocationFailed { .. } | BuildError::InternalInvariant(_),
            ..
        }) => BytesSetBuildAttempt::Fault(fault("build.bytes-set-pattern-internal-fault")),
        Err(PortableRegexSetBuildError::Pattern {
            source: BuildError::Syntax(error),
            ..
        }) if matches!(
            &error.category,
            ErrorCategory::FreResourceLimit { .. }
                | ErrorCategory::StrictQualificationFailure { .. }
        ) =>
        {
            BytesSetBuildAttempt::Unsupported(unsupported(
                CapabilityId::RustBytesSetFacade,
                "build.bytes-set-syntax-resource-envelope",
            ))
        }
        Err(PortableRegexSetBuildError::Pattern { .. }) => {
            BytesSetBuildAttempt::Unsupported(unsupported(
                CapabilityId::RustBytesSetFacade,
                "build.bytes-set-portable-subset-gap",
            ))
        }
        Err(
            PortableRegexSetBuildError::PatternLimit { .. }
            | PortableRegexSetBuildError::PatternBytesLimit { .. }
            | PortableRegexSetBuildError::PersistentLimit { .. },
        ) => BytesSetBuildAttempt::Unsupported(unsupported(
            CapabilityId::RustBytesSetFacade,
            "build.bytes-set-resource-envelope",
        )),
        Err(
            PortableRegexSetBuildError::AllocationFailed { .. }
            | PortableRegexSetBuildError::ArithmeticOverflow { .. },
        ) => BytesSetBuildAttempt::Fault(fault("build.bytes-set-internal-fault")),
        Err(_) => BytesSetBuildAttempt::Fault(fault("build.bytes-set-unclassified-error")),
    }
}

fn execute_bytes_compile(case: &CaseReceipt, input: &ExecutableCase) -> AdapterDisposition {
    let expected = SemanticValue::CompileAccepted(case.compiles);
    match build_bytes(case, input) {
        BuildAttempt::Built(_) => compare(&expected, &SemanticValue::CompileAccepted(true)),
        BuildAttempt::Rejected => compare(&expected, &SemanticValue::CompileAccepted(false)),
        BuildAttempt::Unsupported(disposition) | BuildAttempt::Fault(disposition) => disposition,
    }
}

fn execute_bytes_is_match(case: &CaseReceipt, input: &ExecutableCase) -> AdapterDisposition {
    let expected = SemanticValue::IsMatch(!input.expected.is_empty());
    let regex = match build_bytes(case, input) {
        BuildAttempt::Built(regex) => regex,
        BuildAttempt::Rejected => {
            return mismatch(
                &expected,
                &SemanticValue::CompileAccepted(false),
                "compile.unexpected-rejection",
            );
        }
        BuildAttempt::Unsupported(disposition) | BuildAttempt::Fault(disposition) => {
            return disposition;
        }
    };
    match regex.find_window(
        &input.haystack,
        SearchWindow::new(input.bounds.start, input.bounds.end),
        SearchLimits::unlimited(),
    ) {
        Ok((observed, _)) => {
            let observed = observed
                .is_some_and(|matched| !case.anchored || matched.start() == input.bounds.start);
            compare(&expected, &SemanticValue::IsMatch(observed))
        }
        Err(_) => unsupported(
            CapabilityId::RustBytesFacade,
            "search.portable-execution-refused",
        ),
    }
}

fn execute_bytes_find(case: &CaseReceipt, input: &ExecutableCase) -> AdapterDisposition {
    let Ok(expected_spans) = expected_spans(input) else {
        return fault("adapter.expected-group-zero-missing");
    };
    let expected = SemanticValue::Matches(expected_spans);
    if case.search_kind == SearchKind::Overlapping {
        return execute_bytes_overlapping(case, input, &expected, true);
    }
    if case.search_kind == SearchKind::Earliest || case.match_kind == MatchKind::All {
        return execute_bytes_capture_find(case, input, &expected);
    }
    let regex = match build_bytes(case, input) {
        BuildAttempt::Built(regex) => regex,
        BuildAttempt::Rejected => {
            return mismatch(
                &expected,
                &SemanticValue::CompileAccepted(false),
                "compile.unexpected-rejection",
            );
        }
        BuildAttempt::Unsupported(disposition) | BuildAttempt::Fault(disposition) => {
            return disposition;
        }
    };
    match collect_byte_matches(
        &regex,
        &input.haystack,
        input.bounds,
        case.match_limit,
        case.anchored,
    ) {
        Ok(observed) => compare(&expected, &SemanticValue::Matches(observed)),
        Err(_) => unsupported(
            CapabilityId::RustBytesFacade,
            "search.portable-execution-refused",
        ),
    }
}

fn execute_bytes_capture_find(
    case: &CaseReceipt,
    input: &ExecutableCase,
    expected: &SemanticValue,
) -> AdapterDisposition {
    let regex = match build_captures(case, input) {
        CaptureBuildAttempt::Built(regex) => regex,
        CaptureBuildAttempt::Rejected => {
            return mismatch(
                expected,
                &SemanticValue::CompileAccepted(false),
                "compile.unexpected-rejection",
            );
        }
        CaptureBuildAttempt::Unsupported(disposition) | CaptureBuildAttempt::Fault(disposition) => {
            return disposition;
        }
    };
    let config = match capture_search_config(case) {
        Ok(config) => config,
        Err(disposition) => return disposition,
    };
    let Ok(report) = regex.captures_iter_window_with_config(
        &input.haystack,
        CaptureWindow {
            start: input.bounds.start,
            end: input.bounds.end,
        },
        config,
        CaptureAggregateLimits::default(),
    ) else {
        return unsupported(
            CapabilityId::CaptureIteration,
            "search.bytes-configured-execution-refused",
        );
    };
    let Ok(mut observed) = capture_records(&report.captures, input.haystack.len()) else {
        return fault("adapter.bytes-earliest-record-invariant");
    };
    if case.anchored {
        let Ok(filtered) = anchored_capture_prefix(observed, input.bounds, None) else {
            return fault("adapter.bytes-earliest-anchored-invariant");
        };
        observed = filtered;
    }
    let Ok(mut spans) = group_zero_spans(&observed) else {
        return fault("adapter.bytes-earliest-group-zero-invariant");
    };
    if let Some(limit) = case.match_limit {
        spans.truncate(limit);
    }
    compare(expected, &SemanticValue::Matches(spans))
}

fn group_zero_spans(records: &[ExpectedCaptures]) -> Result<Vec<ExpectedSpan>, ()> {
    records
        .iter()
        .map(|record| record.groups.first().copied().flatten().ok_or(()))
        .collect()
}

/// Execute Rust's low-level overlapping iterator semantics through bounded
/// exact-span capture queries. Forward match ends are visited left-to-right;
/// exact starts for each end are visited right-to-left. `MatchKind::All`
/// admits every exact span. `LeftmostFirst` retains only ends that an ordinary
/// prioritized search would select when clipped at that end, reproducing the
/// forward automaton's preference pruning without depending on expected data.
fn execute_text_overlapping(
    case: &CaseReceipt,
    input: &ExecutableCase,
    expected: &SemanticValue,
    spans_only: bool,
) -> AdapterDisposition {
    let regex = match build_text_captures(case, input) {
        TextCaptureBuildAttempt::Built(regex) => regex,
        TextCaptureBuildAttempt::Rejected => {
            return mismatch(
                expected,
                &SemanticValue::CompileAccepted(false),
                "compile.unexpected-rejection",
            );
        }
        TextCaptureBuildAttempt::Unsupported(disposition)
        | TextCaptureBuildAttempt::Fault(disposition) => return disposition,
    };
    let Ok(haystack) = std::str::from_utf8(&input.haystack) else {
        return fault("adapter.text-haystack-invalid-utf8");
    };
    let Ok(records) = collect_text_overlapping_captures(
        &regex,
        haystack,
        input.bounds,
        case.match_kind,
        case.match_limit,
        case.anchored,
    ) else {
        return unsupported(
            CapabilityId::CaptureIteration,
            "search.text-overlapping-execution-refused",
        );
    };
    if spans_only {
        let Ok(spans) = group_zero_spans(&records) else {
            return fault("adapter.text-overlapping-group-zero-invariant");
        };
        compare(expected, &SemanticValue::Matches(spans))
    } else {
        compare(expected, &SemanticValue::Captures(records))
    }
}

fn execute_bytes_overlapping(
    case: &CaseReceipt,
    input: &ExecutableCase,
    expected: &SemanticValue,
    spans_only: bool,
) -> AdapterDisposition {
    let regex = match build_captures(case, input) {
        CaptureBuildAttempt::Built(regex) => regex,
        CaptureBuildAttempt::Rejected => {
            return mismatch(
                expected,
                &SemanticValue::CompileAccepted(false),
                "compile.unexpected-rejection",
            );
        }
        CaptureBuildAttempt::Unsupported(disposition) | CaptureBuildAttempt::Fault(disposition) => {
            return disposition;
        }
    };
    let Ok(records) = collect_byte_overlapping_captures(
        &regex,
        &input.haystack,
        input.bounds,
        case.match_kind,
        case.match_limit,
        case.anchored,
    ) else {
        return unsupported(
            CapabilityId::CaptureIteration,
            "search.bytes-overlapping-execution-refused",
        );
    };
    if spans_only {
        let Ok(spans) = group_zero_spans(&records) else {
            return fault("adapter.bytes-overlapping-group-zero-invariant");
        };
        compare(expected, &SemanticValue::Matches(spans))
    } else {
        compare(expected, &SemanticValue::Captures(records))
    }
}

fn collect_text_overlapping_captures(
    regex: &PortableTextCaptureRegex,
    haystack: &str,
    bounds: SearchBounds,
    match_kind: MatchKind,
    match_limit: Option<usize>,
    anchored: bool,
) -> Result<Vec<ExpectedCaptures>, ()> {
    let limit = match_limit.unwrap_or(usize::MAX);
    let mut records = Vec::new();
    if limit == 0 {
        return Ok(records);
    }
    if anchored
        && (bounds.start > bounds.end
            || bounds.end > haystack.len()
            || !haystack.is_char_boundary(bounds.start))
    {
        return Ok(records);
    }
    let Some(bounds) = text_search_bounds(haystack, bounds) else {
        return Ok(records);
    };
    let window = CaptureWindow {
        start: bounds.start,
        end: bounds.end,
    };
    for end in bounds.start..=bounds.end {
        if !haystack.is_char_boundary(end) {
            continue;
        }
        if match_kind == MatchKind::LeftmostFirst
            && !text_leftmost_overlapping_end(regex, haystack, bounds, end, anchored)?
        {
            continue;
        }
        for start in (bounds.start..=end).rev() {
            if !haystack.is_char_boundary(start) {
                continue;
            }
            if anchored && start != bounds.start {
                continue;
            }
            let (captures, _) = regex
                .captures_exact_window(
                    haystack,
                    window,
                    CaptureSpan { start, end },
                    CaptureSearchLimits::default(),
                )
                .map_err(|_| ())?;
            let Some(captures) = captures else {
                continue;
            };
            records.push(text_capture_record(&captures)?);
            if records.len() == limit {
                return Ok(records);
            }
        }
    }
    Ok(records)
}

fn text_leftmost_overlapping_end(
    regex: &PortableTextCaptureRegex,
    haystack: &str,
    bounds: SearchBounds,
    end: usize,
    anchored: bool,
) -> Result<bool, ()> {
    let (captures, _) = regex
        .captures_window_with_config(
            haystack,
            CaptureWindow {
                start: bounds.start,
                end,
            },
            CaptureSearchConfig::LEFTMOST.anchored(anchored),
            CaptureSearchLimits::default(),
        )
        .map_err(|_| ())?;
    Ok(captures
        .and_then(|captures| captures.get(0))
        .is_some_and(|matched| matched.end() == end))
}

fn text_capture_record(captures: &PortableTextCaptures<'_>) -> Result<ExpectedCaptures, ()> {
    let groups = (0..captures.len())
        .map(|index| {
            captures.get(index).map(|matched| ExpectedSpan {
                start: matched.start(),
                end: matched.end(),
            })
        })
        .collect::<Vec<_>>();
    if groups.first().is_none_or(Option::is_none) {
        return Err(());
    }
    Ok(ExpectedCaptures {
        pattern_id: 0,
        groups,
    })
}

fn collect_byte_overlapping_captures(
    regex: &CaptureRegex,
    haystack: &[u8],
    bounds: SearchBounds,
    match_kind: MatchKind,
    match_limit: Option<usize>,
    anchored: bool,
) -> Result<Vec<ExpectedCaptures>, ()> {
    let limit = match_limit.unwrap_or(usize::MAX);
    let mut records = Vec::new();
    if limit == 0 || bounds.start > bounds.end || bounds.end > haystack.len() {
        return Ok(records);
    }
    let window = CaptureWindow {
        start: bounds.start,
        end: bounds.end,
    };
    for end in bounds.start..=bounds.end {
        if match_kind == MatchKind::LeftmostFirst
            && !byte_leftmost_overlapping_end(regex, haystack, bounds, end, anchored)?
        {
            continue;
        }
        for start in (bounds.start..=end).rev() {
            if anchored && start != bounds.start {
                continue;
            }
            let outcome = regex
                .captures_exact_window(
                    haystack,
                    window,
                    CaptureSpan { start, end },
                    CaptureSearchLimits::default(),
                )
                .map_err(|_| ())?;
            let Some(record) = outcome.captures else {
                continue;
            };
            records.push(capture_record(&record, haystack.len())?);
            if records.len() == limit {
                return Ok(records);
            }
        }
    }
    Ok(records)
}

fn byte_leftmost_overlapping_end(
    regex: &CaptureRegex,
    haystack: &[u8],
    bounds: SearchBounds,
    end: usize,
    anchored: bool,
) -> Result<bool, ()> {
    let outcome = regex
        .captures_window_with_config(
            haystack,
            CaptureWindow {
                start: bounds.start,
                end,
            },
            CaptureSearchConfig::LEFTMOST.anchored(anchored),
            CaptureSearchLimits::default(),
        )
        .map_err(|_| ())?;
    Ok(outcome
        .captures
        .and_then(|record| record.overall())
        .is_some_and(|matched| matched.end == end))
}

fn capture_record(
    record: &fre::CaptureRecord,
    haystack_len: usize,
) -> Result<ExpectedCaptures, ()> {
    let mut records =
        capture_records(std::slice::from_ref(record), haystack_len).map_err(|_| ())?;
    records.pop().ok_or(())
}

fn collect_text_matches(
    regex: &PortableTextRegex,
    haystack: &str,
    bounds: SearchBounds,
    match_limit: Option<usize>,
    anchored: bool,
) -> Result<Vec<ExpectedSpan>, PortableTextSearchError> {
    let limit = match_limit.unwrap_or(usize::MAX);
    let mut spans = Vec::new();
    if anchored
        && (bounds.start > bounds.end
            || bounds.end > haystack.len()
            || !haystack.is_char_boundary(bounds.start))
    {
        return Ok(spans);
    }
    let Some(bounds) = text_search_bounds(haystack, bounds) else {
        return Ok(spans);
    };
    let mut start = bounds.start;
    let mut last_match_end = None;
    while spans.len() < limit {
        if anchored && !haystack.is_char_boundary(start) {
            break;
        }
        let (matched, _) = regex.find_window(
            haystack,
            SearchWindow::new(start, bounds.end),
            SearchLimits::unlimited(),
        )?;
        let Some(matched) = matched else {
            break;
        };
        if anchored && matched.start() != start {
            break;
        }
        if matched.is_empty() && last_match_end == Some(matched.end()) {
            if start == bounds.end {
                break;
            }
            start = if anchored {
                start.saturating_add(1).min(bounds.end)
            } else {
                next_text_boundary(haystack, start.saturating_add(1), bounds.end)
            };
            continue;
        }
        spans.push(ExpectedSpan {
            start: matched.start(),
            end: matched.end(),
        });
        start = matched.end();
        last_match_end = Some(matched.end());
    }
    Ok(spans)
}

fn collect_byte_matches(
    regex: &PortableRegex,
    haystack: &[u8],
    bounds: SearchBounds,
    match_limit: Option<usize>,
    anchored: bool,
) -> Result<Vec<ExpectedSpan>, SearchError> {
    let limit = match_limit.unwrap_or(usize::MAX);
    let mut spans = Vec::new();
    let mut start = bounds.start;
    let mut last_match_end = None;
    while spans.len() < limit {
        let (matched, _) = regex.find_window(
            haystack,
            SearchWindow::new(start, bounds.end),
            SearchLimits::unlimited(),
        )?;
        let Some(matched) = matched else {
            break;
        };
        if anchored && matched.start() != start {
            break;
        }
        if matched.is_empty() && last_match_end == Some(matched.end()) {
            if start == bounds.end {
                break;
            }
            start = start.saturating_add(1);
            continue;
        }
        spans.push(ExpectedSpan {
            start: matched.start(),
            end: matched.end(),
        });
        start = matched.end();
        last_match_end = Some(matched.end());
    }
    Ok(spans)
}

fn next_text_boundary(haystack: &str, start: usize, end: usize) -> usize {
    let mut boundary = start.min(end);
    while boundary < end && !haystack.is_char_boundary(boundary) {
        boundary = boundary.saturating_add(1);
    }
    boundary
}

fn text_search_bounds(haystack: &str, bounds: SearchBounds) -> Option<SearchBounds> {
    if bounds.start > bounds.end || bounds.end > haystack.len() {
        return None;
    }
    let mut start = bounds.start;
    while start <= bounds.end && !haystack.is_char_boundary(start) {
        start = start.saturating_add(1);
    }
    let mut end = bounds.end;
    while end >= start && !haystack.is_char_boundary(end) {
        end = end.saturating_sub(1);
    }
    (start <= end).then_some(SearchBounds { start, end })
}

fn execute_text_captures(case: &CaseReceipt, input: &ExecutableCase) -> AdapterDisposition {
    let expected = SemanticValue::Captures(input.expected.clone());
    if case.search_kind == SearchKind::Overlapping {
        return execute_text_overlapping(case, input, &expected, false);
    }
    let regex = match build_text_captures(case, input) {
        TextCaptureBuildAttempt::Built(regex) => regex,
        TextCaptureBuildAttempt::Rejected => {
            return mismatch(
                &expected,
                &SemanticValue::CompileAccepted(false),
                "compile.unexpected-rejection",
            );
        }
        TextCaptureBuildAttempt::Unsupported(disposition) => {
            return execute_capture_free_text_captures(case, input, &expected, disposition);
        }
        TextCaptureBuildAttempt::Fault(disposition) => return disposition,
    };
    let Ok(haystack) = std::str::from_utf8(&input.haystack) else {
        return fault("adapter.text-haystack-invalid-utf8");
    };
    let Some(bounds) = text_search_bounds(haystack, input.bounds) else {
        return compare(&expected, &SemanticValue::Captures(Vec::new()));
    };
    let config = match capture_search_config(case) {
        Ok(config) => config,
        Err(disposition) => return disposition,
    };
    let Ok(report) = regex.captures_iter_window_with_config(
        haystack,
        CaptureWindow {
            start: bounds.start,
            end: bounds.end,
        },
        config,
        CaptureAggregateLimits::default(),
    ) else {
        return unsupported(
            CapabilityId::CaptureIteration,
            "search.text-capture-execution-refused",
        );
    };
    let Ok(mut observed) = capture_records(&report.captures, input.haystack.len()) else {
        return fault("adapter.text-capture-record-invariant");
    };
    if case.anchored {
        let Ok(filtered) = anchored_capture_prefix(observed, input.bounds, Some(haystack)) else {
            return fault("adapter.text-anchored-capture-invariant");
        };
        observed = filtered;
    }
    if let Some(limit) = case.match_limit {
        observed.truncate(limit);
    }
    compare(&expected, &SemanticValue::Captures(observed))
}

/// Execute the complete capture surface through the ordinary text matcher
/// only when three independent build facts prove that group zero is the sole
/// capture slot. This avoids constructing the persistent-history engine for
/// capture-free patterns whose large counted repetition or Unicode class is
/// outside that engine's intentionally smaller resource envelope.
fn execute_capture_free_text_captures(
    case: &CaseReceipt,
    input: &ExecutableCase,
    expected: &SemanticValue,
    original: AdapterDisposition,
) -> AdapterDisposition {
    if case.search_kind != SearchKind::Leftmost || case.match_kind != MatchKind::LeftmostFirst {
        return original;
    }
    let regex = match build_text(case, input) {
        TextBuildAttempt::Built(regex) => regex,
        TextBuildAttempt::Rejected
        | TextBuildAttempt::Unsupported(_)
        | TextBuildAttempt::Fault(_) => return original,
    };
    let report = regex.build_report();
    if report.text_syntax.captures != 0
        || report.bytes_syntax.captures != 0
        || report.portable.captures_len != 1
    {
        return original;
    }
    let Ok(haystack) = std::str::from_utf8(&input.haystack) else {
        return fault("adapter.text-haystack-invalid-utf8");
    };
    let Ok(spans) = collect_text_matches(
        &regex,
        haystack,
        input.bounds,
        case.match_limit,
        case.anchored,
    ) else {
        return unsupported(
            CapabilityId::CaptureIteration,
            "search.text-capture-free-execution-refused",
        );
    };
    let observed = spans
        .into_iter()
        .map(|span| ExpectedCaptures {
            pattern_id: 0,
            groups: vec![Some(span)],
        })
        .collect();
    compare(expected, &SemanticValue::Captures(observed))
}

fn build_text_captures(case: &CaseReceipt, input: &ExecutableCase) -> TextCaptureBuildAttempt {
    let Some(pattern) = input.patterns.first() else {
        return TextCaptureBuildAttempt::Fault(fault("adapter.single-pattern-missing"));
    };
    let mut profile = RustProfile::default();
    profile.options.case_insensitive = case.case_insensitive;
    profile.options.unicode = case.unicode;
    profile.options.line_terminator = input.line_terminator;
    match PortableTextCaptureBuilder::new(pattern.clone())
        .profile(profile)
        .build()
    {
        Ok(regex) => TextCaptureBuildAttempt::Built(Box::new(regex)),
        Err(PortableTextCaptureBuildError::TextSyntax(error))
            if matches!(&error.category, ErrorCategory::UpstreamRustSyntax) =>
        {
            TextCaptureBuildAttempt::Rejected
        }
        Err(
            PortableTextCaptureBuildError::InternalInvariant(_)
            | PortableTextCaptureBuildError::Capture(CaptureBuildError::InternalInvariant(_)),
        ) => TextCaptureBuildAttempt::Fault(fault("build.text-capture-internal-fault")),
        Err(
            PortableTextCaptureBuildError::BytesProofSyntax(_)
            | PortableTextCaptureBuildError::ProfileHirMismatch
            | PortableTextCaptureBuildError::InvalidUtf8Hir,
        ) => TextCaptureBuildAttempt::Unsupported(unsupported(
            CapabilityId::CaptureIteration,
            "build.text-capture-equivalence-gap",
        )),
        Err(PortableTextCaptureBuildError::Capture(_)) => TextCaptureBuildAttempt::Unsupported(
            unsupported(CapabilityId::CaptureIteration, "build.capture-subset-gap"),
        ),
        Err(PortableTextCaptureBuildError::TextSyntax(_)) => {
            TextCaptureBuildAttempt::Fault(fault("build.text-capture-unexpected-syntax"))
        }
        Err(_) => TextCaptureBuildAttempt::Fault(fault("build.text-capture-unclassified-error")),
    }
}

fn execute_bytes_captures(case: &CaseReceipt, input: &ExecutableCase) -> AdapterDisposition {
    let expected = SemanticValue::Captures(input.expected.clone());
    if case.search_kind == SearchKind::Overlapping {
        return execute_bytes_overlapping(case, input, &expected, false);
    }
    let regex = match build_captures(case, input) {
        CaptureBuildAttempt::Built(regex) => regex,
        CaptureBuildAttempt::Rejected => {
            return mismatch(
                &expected,
                &SemanticValue::CompileAccepted(false),
                "compile.unexpected-rejection",
            );
        }
        CaptureBuildAttempt::Unsupported(disposition) | CaptureBuildAttempt::Fault(disposition) => {
            return disposition;
        }
    };
    let config = match capture_search_config(case) {
        Ok(config) => config,
        Err(disposition) => return disposition,
    };
    let Ok(report) = regex.captures_iter_window_with_config(
        &input.haystack,
        CaptureWindow {
            start: input.bounds.start,
            end: input.bounds.end,
        },
        config,
        CaptureAggregateLimits::default(),
    ) else {
        return unsupported(
            CapabilityId::CaptureIteration,
            "search.capture-execution-refused",
        );
    };
    let Ok(mut observed) = capture_records(&report.captures, input.haystack.len()) else {
        return fault("adapter.capture-record-invariant");
    };
    if case.anchored {
        let Ok(filtered) = anchored_capture_prefix(observed, input.bounds, None) else {
            return fault("adapter.anchored-capture-invariant");
        };
        observed = filtered;
    }
    if let Some(limit) = case.match_limit {
        observed.truncate(limit);
    }
    compare(&expected, &SemanticValue::Captures(observed))
}

fn capture_search_config(case: &CaseReceipt) -> Result<CaptureSearchConfig, AdapterDisposition> {
    let config = match case.search_kind {
        SearchKind::Leftmost => CaptureSearchConfig::LEFTMOST,
        SearchKind::Earliest => CaptureSearchConfig::EARLIEST,
        SearchKind::Overlapping => {
            return Err(fault("adapter.capture-search-policy-invariant"));
        }
    };
    let match_kind = match case.match_kind {
        MatchKind::All => CaptureMatchKind::All,
        MatchKind::LeftmostFirst => CaptureMatchKind::LeftmostFirst,
        MatchKind::LeftmostLongest => {
            return Err(fault("adapter.capture-match-policy-invariant"));
        }
    };
    Ok(config.match_kind(match_kind).anchored(case.anchored))
}

fn build_captures(case: &CaseReceipt, input: &ExecutableCase) -> CaptureBuildAttempt {
    let Some(pattern) = input.patterns.first() else {
        return CaptureBuildAttempt::Fault(fault("adapter.single-pattern-missing"));
    };
    let mut profile = RustProfile::default();
    profile.options.case_insensitive = case.case_insensitive;
    profile.options.unicode = case.unicode;
    profile.options.line_terminator = input.line_terminator;
    match CaptureBuilder::new(pattern.clone())
        .profile(profile)
        .build()
    {
        Ok(regex) => CaptureBuildAttempt::Built(Box::new(regex)),
        Err(CaptureBuildError::Syntax(error))
            if matches!(&error.category, ErrorCategory::UpstreamRustSyntax) =>
        {
            CaptureBuildAttempt::Rejected
        }
        Err(CaptureBuildError::InternalInvariant(_)) => {
            CaptureBuildAttempt::Fault(fault("build.capture-internal-fault"))
        }
        Err(_) => CaptureBuildAttempt::Unsupported(unsupported(
            CapabilityId::CaptureIteration,
            "build.capture-subset-gap",
        )),
    }
}

fn capture_records(
    records: &[fre::CaptureRecord],
    haystack_len: usize,
) -> Result<Vec<ExpectedCaptures>, InventoryError> {
    records
        .iter()
        .map(|record| {
            let groups = record
                .groups
                .iter()
                .enumerate()
                .map(|(index, group)| {
                    if usize::try_from(group.index).ok() != Some(index) {
                        return Err(InventoryError::new(
                            "capture group records are not in numeric order",
                        ));
                    }
                    group
                        .span
                        .map(|span| {
                            if span.start > span.end || span.end > haystack_len {
                                return Err(InventoryError::new(
                                    "capture group record is outside the haystack",
                                ));
                            }
                            Ok(ExpectedSpan {
                                start: span.start,
                                end: span.end,
                            })
                        })
                        .transpose()
                })
                .collect::<Result<Vec<_>, _>>()?;
            if groups.first().is_none_or(Option::is_none) {
                return Err(InventoryError::new(
                    "capture record lacks participating group zero",
                ));
            }
            Ok(ExpectedCaptures {
                pattern_id: 0,
                groups,
            })
        })
        .collect()
}

fn anchored_capture_prefix(
    records: Vec<ExpectedCaptures>,
    bounds: SearchBounds,
    text_haystack: Option<&str>,
) -> Result<Vec<ExpectedCaptures>, InventoryError> {
    if bounds.start > bounds.end {
        return Err(InventoryError::new("anchored capture bounds are reversed"));
    }
    let mut restart = bounds.start;
    let mut retained = Vec::new();
    for record in records {
        if restart > bounds.end {
            break;
        }
        if text_haystack.is_some_and(|haystack| !haystack.is_char_boundary(restart)) {
            break;
        }
        let span = record
            .groups
            .first()
            .and_then(|group| *group)
            .ok_or_else(|| InventoryError::new("anchored capture lacks group zero"))?;
        if span.start != restart {
            break;
        }
        if span.end > bounds.end {
            return Err(InventoryError::new(
                "anchored capture extends beyond search bounds",
            ));
        }
        restart = if span.start == span.end {
            restart.saturating_add(1)
        } else {
            span.end
        };
        retained.push(record);
    }
    Ok(retained)
}

fn expected_spans(input: &ExecutableCase) -> Result<Vec<ExpectedSpan>, InventoryError> {
    input
        .expected
        .iter()
        .map(|matched| {
            matched
                .groups
                .first()
                .and_then(|group| *group)
                .ok_or_else(|| InventoryError::new("expected match lacks participating group zero"))
        })
        .collect()
}

fn build_bytes(case: &CaseReceipt, input: &ExecutableCase) -> BuildAttempt {
    let Some(pattern) = input.patterns.first() else {
        return BuildAttempt::Fault(fault("adapter.single-pattern-missing"));
    };
    build_bytes_pattern(case, input, pattern)
}

fn build_bytes_pattern(case: &CaseReceipt, input: &ExecutableCase, pattern: &str) -> BuildAttempt {
    let mut profile = RustProfile::default();
    profile.options.case_insensitive = case.case_insensitive;
    profile.options.unicode = case.unicode;
    profile.options.line_terminator = input.line_terminator;
    match PortableBuilder::new(pattern.to_owned())
        .profile(profile)
        .build()
    {
        Ok(regex) => BuildAttempt::Built(Box::new(regex)),
        Err(BuildError::Syntax(error))
            if matches!(&error.category, ErrorCategory::UpstreamRustSyntax) =>
        {
            BuildAttempt::Rejected
        }
        Err(BuildError::AllocationFailed { .. } | BuildError::InternalInvariant(_)) => {
            BuildAttempt::Fault(fault("build.portable-internal-fault"))
        }
        Err(BuildError::Syntax(error))
            if matches!(
                &error.category,
                ErrorCategory::FreResourceLimit { .. }
                    | ErrorCategory::StrictQualificationFailure { .. }
            ) =>
        {
            BuildAttempt::Unsupported(unsupported(
                CapabilityId::RustBytesFacade,
                "build.syntax-resource-envelope",
            ))
        }
        Err(_) => BuildAttempt::Unsupported(unsupported(
            CapabilityId::RustBytesFacade,
            "build.portable-subset-gap",
        )),
    }
}

fn surface_applicability(
    surface: AdapterSurface,
    case: &CaseReceipt,
    input: &ExecutableCase,
) -> Result<(), NotApplicableReason> {
    match surface {
        AdapterSurface::RustTextCompile
        | AdapterSurface::RustTextIsMatch
        | AdapterSurface::RustTextFindIter
        | AdapterSurface::RustTextCapturesIter => {
            single_applicability(surface, case, input, true)?;
        }
        AdapterSurface::RustBytesCompile
        | AdapterSurface::RustBytesIsMatch
        | AdapterSurface::RustBytesFindIter
        | AdapterSurface::RustBytesCapturesIter => {
            single_applicability(surface, case, input, false)?;
        }
        AdapterSurface::RustTextSetCompile
        | AdapterSurface::RustTextSetIsMatch
        | AdapterSurface::RustTextSetWhich => {
            if surface != AdapterSurface::RustTextSetWhich
                || multi_pattern_set_selection_applicability(case, input, true).is_err()
            {
                set_applicability(surface, case, input, true)?;
            }
        }
        AdapterSurface::RustBytesSetCompile if case.utf8 => {
            set_applicability(surface, case, input, true)?;
        }
        AdapterSurface::RustBytesSetWhich if case.utf8 && input.patterns.len() > 1 => {
            if multi_pattern_set_selection_applicability(case, input, false).is_err() {
                utf8_bytes_overlapping_all_set_which_applicability(case, input)?;
            }
        }
        AdapterSurface::RustBytesSetCompile
        | AdapterSurface::RustBytesSetIsMatch
        | AdapterSurface::RustBytesSetWhich => {
            if surface != AdapterSurface::RustBytesSetWhich
                || multi_pattern_set_selection_applicability(case, input, false).is_err()
            {
                set_applicability(surface, case, input, false)?;
            }
        }
    }
    if !is_compile_surface(surface) && !case.compiles {
        return Err(NotApplicableReason::CompileOnlyCase);
    }
    Ok(())
}

/// Selection-sensitive multi-pattern observations are evaluated as an
/// ordered union of the already-qualified constituent matchers. Keep this
/// exact domain separate from ordinary `RegexSet` membership: no anchoring,
/// bounds or match-limit approximation is permitted, and text execution still
/// requires the case's UTF-8 profile.
fn multi_pattern_set_selection_applicability(
    case: &CaseReceipt,
    input: &ExecutableCase,
    text: bool,
) -> Result<(), NotApplicableReason> {
    if input.patterns.len() <= 1 {
        return Err(NotApplicableReason::PatternMultiplicity);
    }
    if !matches!(
        (case.search_kind, case.match_kind),
        (
            SearchKind::Leftmost,
            MatchKind::LeftmostFirst | MatchKind::All
        ) | (SearchKind::Overlapping, MatchKind::LeftmostFirst)
    ) {
        return Err(NotApplicableReason::ProfileCannotRepresentSearchMode);
    }
    if case.anchored {
        return Err(NotApplicableReason::ProfileCannotRepresentAnchoring);
    }
    if input.bounds
        != (SearchBounds {
            start: 0,
            end: input.haystack.len(),
        })
        || case.match_limit.is_some()
    {
        return Err(NotApplicableReason::ProfileCannotRepresentBounds);
    }
    if text {
        if !case.utf8 {
            return Err(NotApplicableReason::ProfileCannotRepresentUtf8Mode);
        }
        if std::str::from_utf8(&input.haystack).is_err() {
            return Err(NotApplicableReason::InvalidUtf8Haystack);
        }
    } else if case.utf8 && std::str::from_utf8(&input.haystack).is_err() {
        return Err(NotApplicableReason::InvalidUtf8Haystack);
    }
    Ok(())
}

fn single_applicability(
    surface: AdapterSurface,
    case: &CaseReceipt,
    input: &ExecutableCase,
    text: bool,
) -> Result<(), NotApplicableReason> {
    if input.patterns.len() != 1 {
        return Err(NotApplicableReason::PatternMultiplicity);
    }
    if !single_selection_policy_invariant(surface) {
        // Preserve the authenticated search-mode precedence for text surfaces
        // whose byte-mode corpus profile remains intrinsically ineligible.
        // Eligible overlapping rows proceed into the shared exact-span path.
        if case.search_kind == SearchKind::Overlapping && text && !case.utf8 {
            return Err(NotApplicableReason::ProfileCannotRepresentSearchMode);
        }
        if !matches!(
            (case.search_kind, case.match_kind),
            (
                SearchKind::Leftmost | SearchKind::Overlapping,
                MatchKind::LeftmostFirst | MatchKind::All
            ) | (SearchKind::Earliest, MatchKind::LeftmostFirst)
        ) {
            return Err(NotApplicableReason::ProfileCannotRepresentMatchMode);
        }
    }
    // Preserve the authenticated rejection precedence for a bounded text
    // capture row whose UTF-8 profile is independently ineligible. Eligible
    // text and bytes capture profiles continue into bounded execution below.
    if surface == AdapterSurface::RustTextCapturesIter
        && !case.utf8
        && input.bounds
            != (SearchBounds {
                start: 0,
                end: input.haystack.len(),
            })
    {
        return Err(NotApplicableReason::ProfileCannotRepresentBounds);
    }
    if case.utf8 != text {
        let utf8_bytes_text_delegate = case.utf8
            && matches!(
                surface,
                AdapterSurface::RustBytesIsMatch
                    | AdapterSurface::RustBytesFindIter
                    | AdapterSurface::RustBytesCapturesIter
            );
        if utf8_bytes_text_delegate && std::str::from_utf8(&input.haystack).is_err() {
            return Err(NotApplicableReason::InvalidUtf8Haystack);
        }
        if surface != AdapterSurface::RustBytesCompile && !utf8_bytes_text_delegate {
            return Err(NotApplicableReason::ProfileCannotRepresentUtf8Mode);
        }
    }
    if text && std::str::from_utf8(&input.haystack).is_err() {
        return Err(NotApplicableReason::InvalidUtf8Haystack);
    }
    Ok(())
}

const fn single_selection_policy_invariant(surface: AdapterSurface) -> bool {
    matches!(
        surface,
        AdapterSurface::RustTextCompile
            | AdapterSurface::RustTextIsMatch
            | AdapterSurface::RustBytesCompile
            | AdapterSurface::RustBytesIsMatch
    )
}

fn set_applicability(
    surface: AdapterSurface,
    case: &CaseReceipt,
    input: &ExecutableCase,
    text: bool,
) -> Result<(), NotApplicableReason> {
    // Compilation does not observe search or match-selection policy. Preserve
    // the canonical singleton rejection precedence, and admit larger/empty
    // sets only when the selected compiler profile exactly matches the case.
    if is_compile_surface(surface) && (input.patterns.len() == 1 || case.utf8 == text) {
        if case.utf8 != text {
            return Err(NotApplicableReason::ProfileCannotRepresentUtf8Mode);
        }
        if text && std::str::from_utf8(&input.haystack).is_err() {
            return Err(NotApplicableReason::InvalidUtf8Haystack);
        }
        return Ok(());
    }
    // A singleton set exposes only match existence and the sole pattern ID.
    // Delegate applicability to the corresponding already-qualified single
    // facade so its search policy, anchoring, bounds, and UTF-8 proof remain
    // exact. The execution path separately proves native set compilation.
    if input.patterns.len() == 1 {
        match singleton_set_delegate_applicability(surface, case, input) {
            Ok(()) => return Ok(()),
            Err(NotApplicableReason::InvalidUtf8Haystack) => {
                return Err(NotApplicableReason::InvalidUtf8Haystack);
            }
            Err(NotApplicableReason::ProfileCannotRepresentBounds)
                if case.match_limit == Some(0) =>
            {
                return Err(NotApplicableReason::ProfileCannotRepresentBounds);
            }
            Err(_) => {}
        }
    }
    match selection_invariant_set_observation_applicability(surface, case, input, text) {
        Ok(()) => return Ok(()),
        Err(NotApplicableReason::InvalidUtf8Haystack) => {
            return Err(NotApplicableReason::InvalidUtf8Haystack);
        }
        Err(_) => {}
    }
    if case.search_kind != SearchKind::Overlapping {
        return Err(NotApplicableReason::ProfileCannotRepresentSearchMode);
    }
    if case.match_kind != MatchKind::All {
        return Err(NotApplicableReason::ProfileCannotRepresentMatchMode);
    }
    if case.anchored {
        return Err(NotApplicableReason::ProfileCannotRepresentAnchoring);
    }
    if input.bounds
        != (SearchBounds {
            start: 0,
            end: input.haystack.len(),
        })
    {
        return Err(NotApplicableReason::ProfileCannotRepresentBounds);
    }
    if case.utf8 != text {
        return Err(NotApplicableReason::ProfileCannotRepresentUtf8Mode);
    }
    if text && std::str::from_utf8(&input.haystack).is_err() {
        return Err(NotApplicableReason::InvalidUtf8Haystack);
    }
    Ok(())
}

fn singleton_set_delegate_applicability(
    surface: AdapterSurface,
    case: &CaseReceipt,
    input: &ExecutableCase,
) -> Result<(), NotApplicableReason> {
    if input.patterns.len() != 1 {
        return Err(NotApplicableReason::PatternMultiplicity);
    }
    // Match existence and the sole pattern ID do not depend on search or
    // match-selection policy. A zero match limit still suppresses every
    // observation and must not be replaced by an unconstrained facade call.
    if case.match_limit == Some(0) {
        return Err(NotApplicableReason::ProfileCannotRepresentBounds);
    }
    let (delegate, text) = match surface {
        AdapterSurface::RustTextSetIsMatch | AdapterSurface::RustTextSetWhich => {
            (AdapterSurface::RustTextIsMatch, true)
        }
        AdapterSurface::RustBytesSetIsMatch | AdapterSurface::RustBytesSetWhich => {
            (AdapterSurface::RustBytesIsMatch, false)
        }
        _ => return Err(NotApplicableReason::PatternMultiplicity),
    };
    single_applicability(delegate, case, input, text)
}

/// Match existence is invariant across leftmost, earliest, overlapping, and
/// match-selection policies. The set of matching pattern IDs has the same
/// invariance only when there are zero or one patterns. Keep this adapter
/// delegation restricted to an unanchored full-haystack search, where the
/// native set search domain is exact. This predicate is based only on the
/// requested operation and authenticated case metadata, never expected output.
fn selection_invariant_set_observation_applicability(
    surface: AdapterSurface,
    case: &CaseReceipt,
    input: &ExecutableCase,
    text: bool,
) -> Result<(), NotApplicableReason> {
    match surface {
        AdapterSurface::RustTextSetIsMatch | AdapterSurface::RustBytesSetIsMatch => {}
        AdapterSurface::RustTextSetWhich | AdapterSurface::RustBytesSetWhich
            if input.patterns.len() <= 1 => {}
        _ => return Err(NotApplicableReason::ProfileCannotRepresentSearchMode),
    }
    if case.anchored {
        return Err(NotApplicableReason::ProfileCannotRepresentAnchoring);
    }
    if input.bounds
        != (SearchBounds {
            start: 0,
            end: input.haystack.len(),
        })
        || case.match_limit == Some(0)
    {
        return Err(NotApplicableReason::ProfileCannotRepresentBounds);
    }
    if case.utf8 != text {
        let utf8_bytes_text_set_delegate = case.utf8
            && !text
            && matches!(
                surface,
                AdapterSurface::RustBytesSetIsMatch | AdapterSurface::RustBytesSetWhich
            );
        if utf8_bytes_text_set_delegate && std::str::from_utf8(&input.haystack).is_err() {
            return Err(NotApplicableReason::InvalidUtf8Haystack);
        }
        if !utf8_bytes_text_set_delegate {
            return Err(NotApplicableReason::ProfileCannotRepresentUtf8Mode);
        }
    }
    if text && std::str::from_utf8(&input.haystack).is_err() {
        return Err(NotApplicableReason::InvalidUtf8Haystack);
    }
    Ok(())
}

/// A UTF-8 bytes `RegexSet` with overlapping/all semantics asks for every
/// matching pattern ID in an unbounded haystack. That observation is exactly
/// the already-qualified text-set `matches` operation after the same UTF-8
/// profile proof used for bytes-set compilation. Keep this delegation narrow:
/// selection-sensitive modes, anchors, bounds, limits and invalid UTF-8 stay
/// outside the admitted domain.
fn utf8_bytes_overlapping_all_set_which_applicability(
    case: &CaseReceipt,
    input: &ExecutableCase,
) -> Result<(), NotApplicableReason> {
    if input.patterns.len() <= 1 {
        return Err(NotApplicableReason::PatternMultiplicity);
    }
    if case.search_kind != SearchKind::Overlapping {
        return Err(NotApplicableReason::ProfileCannotRepresentSearchMode);
    }
    if case.match_kind != MatchKind::All {
        return Err(NotApplicableReason::ProfileCannotRepresentMatchMode);
    }
    if case.anchored {
        return Err(NotApplicableReason::ProfileCannotRepresentAnchoring);
    }
    if input.bounds
        != (SearchBounds {
            start: 0,
            end: input.haystack.len(),
        })
    {
        return Err(NotApplicableReason::ProfileCannotRepresentBounds);
    }
    // Preserve the existing bytes-profile refusal for every excluded UTF-8
    // row so this new lane cannot rewrite non-gain N/A evidence.
    if !case.utf8 || case.match_limit.is_some() || std::str::from_utf8(&input.haystack).is_err() {
        return Err(NotApplicableReason::ProfileCannotRepresentUtf8Mode);
    }
    Ok(())
}

const fn is_compile_surface(surface: AdapterSurface) -> bool {
    matches!(
        surface,
        AdapterSurface::RustTextCompile
            | AdapterSurface::RustBytesCompile
            | AdapterSurface::RustTextSetCompile
            | AdapterSurface::RustBytesSetCompile
    )
}

fn compare(expected: &SemanticValue, observed: &SemanticValue) -> AdapterDisposition {
    let expected_sha256 = semantic_hash(expected);
    let observed_sha256 = semantic_hash(observed);
    if expected_sha256 == observed_sha256 {
        AdapterDisposition::Pass {
            expected_sha256,
            observed_sha256,
        }
    } else {
        AdapterDisposition::Mismatch {
            expected_sha256,
            observed_sha256,
            reason_code: "semantic.value-mismatch".to_owned(),
        }
    }
}

fn mismatch(
    expected: &SemanticValue,
    observed: &SemanticValue,
    reason: &str,
) -> AdapterDisposition {
    AdapterDisposition::Mismatch {
        expected_sha256: semantic_hash(expected),
        observed_sha256: semantic_hash(observed),
        reason_code: reason.to_owned(),
    }
}

fn semantic_hash(value: &SemanticValue) -> String {
    sha256(&serde_json::to_vec(value).expect("semantic values always serialize"))
}

fn unsupported(capability: CapabilityId, reason: &str) -> AdapterDisposition {
    AdapterDisposition::Unsupported {
        capability,
        reason_code: reason.to_owned(),
    }
}

fn fault(reason: &str) -> AdapterDisposition {
    AdapterDisposition::Fault {
        reason_code: reason.to_owned(),
    }
}

fn decode_executable_case(id: String, raw: &RawCase) -> Result<ExecutableCase, InventoryError> {
    let patterns = match &raw.regex {
        toml::Value::String(pattern) => vec![pattern.clone()],
        toml::Value::Array(patterns) => patterns
            .iter()
            .map(|pattern| {
                pattern
                    .as_str()
                    .map(str::to_owned)
                    .ok_or_else(|| InventoryError::new("regex array contains non-string"))
            })
            .collect::<Result<Vec<_>, _>>()?,
        _ => return Err(InventoryError::new("regex value is not string or array")),
    };
    let haystack = if raw.unescape {
        Vec::unescape_bytes(&raw.haystack)
    } else {
        raw.haystack.as_bytes().to_vec()
    };
    let bounds = decode_bounds(raw.bounds.as_ref(), haystack.len())?;
    let line_terminator = if raw.line_terminator.is_empty() {
        b'\n'
    } else {
        let bytes = Vec::unescape_bytes(&raw.line_terminator);
        if bytes.len() != 1 {
            return Err(InventoryError::new(format!(
                "case {id} line terminator is not one byte"
            )));
        }
        bytes[0]
    };
    let expected = raw
        .matches
        .iter()
        .map(|value| decode_expected(value, patterns.len(), haystack.len()))
        .collect::<Result<Vec<_>, _>>()?;
    Ok(ExecutableCase {
        id,
        patterns,
        haystack,
        bounds,
        line_terminator,
        expected,
    })
}

fn decode_bounds(
    value: Option<&toml::Value>,
    haystack_len: usize,
) -> Result<SearchBounds, InventoryError> {
    let Some(value) = value else {
        return Ok(SearchBounds {
            start: 0,
            end: haystack_len,
        });
    };
    let (start, end) = match value {
        toml::Value::Array(values) if values.len() == 2 => {
            (values[0].as_integer(), values[1].as_integer())
        }
        toml::Value::Table(table) => (
            table.get("start").and_then(toml::Value::as_integer),
            table.get("end").and_then(toml::Value::as_integer),
        ),
        _ => (None, None),
    };
    let (Some(start), Some(end)) = (start, end) else {
        return Err(InventoryError::new("invalid executable search bounds"));
    };
    let start = usize::try_from(start)
        .map_err(|_| InventoryError::new("negative executable search start"))?;
    let end =
        usize::try_from(end).map_err(|_| InventoryError::new("negative executable search end"))?;
    if start > end || end > haystack_len {
        return Err(InventoryError::new("executable search bounds out of range"));
    }
    Ok(SearchBounds { start, end })
}

fn decode_expected(
    value: &toml::Value,
    pattern_count: usize,
    haystack_len: usize,
) -> Result<ExpectedCaptures, InventoryError> {
    let (pattern_id, groups) = match value {
        toml::Value::Array(values)
            if values.len() == 2 && values.iter().all(toml::Value::is_integer) =>
        {
            (0, vec![Some(decode_span(values, haystack_len)?)])
        }
        toml::Value::Array(values) => (
            0,
            values
                .iter()
                .map(|span| decode_maybe_span(span, haystack_len))
                .collect::<Result<Vec<_>, _>>()?,
        ),
        toml::Value::Table(table) if table.contains_key("span") => {
            if table.len() != 2 || !table.contains_key("id") {
                return Err(InventoryError::new("invalid expected match table keys"));
            }
            let id = decode_nonnegative(table.get("id"), "expected pattern ID")?;
            let span = table
                .get("span")
                .and_then(toml::Value::as_array)
                .ok_or_else(|| InventoryError::new("expected span is not an array"))?;
            (id, vec![Some(decode_span(span, haystack_len)?)])
        }
        toml::Value::Table(table) if table.contains_key("spans") => {
            if table.len() != 2 || !table.contains_key("id") {
                return Err(InventoryError::new("invalid expected captures table keys"));
            }
            let id = decode_nonnegative(table.get("id"), "expected pattern ID")?;
            let spans = table
                .get("spans")
                .and_then(toml::Value::as_array)
                .ok_or_else(|| InventoryError::new("expected spans is not an array"))?;
            (
                id,
                spans
                    .iter()
                    .map(|span| decode_maybe_span(span, haystack_len))
                    .collect::<Result<Vec<_>, _>>()?,
            )
        }
        _ => {
            return Err(InventoryError::new(
                "unrecognized executable expected match",
            ));
        }
    };
    if pattern_id >= pattern_count {
        return Err(InventoryError::new("expected pattern ID is out of range"));
    }
    if groups.is_empty() || groups[0].is_none() {
        return Err(InventoryError::new(
            "expected captures lack participating group zero",
        ));
    }
    Ok(ExpectedCaptures { pattern_id, groups })
}

fn decode_maybe_span(
    value: &toml::Value,
    haystack_len: usize,
) -> Result<Option<ExpectedSpan>, InventoryError> {
    let values = value
        .as_array()
        .ok_or_else(|| InventoryError::new("expected capture span is not an array"))?;
    if values.is_empty() {
        Ok(None)
    } else {
        decode_span(values, haystack_len).map(Some)
    }
}

fn decode_span(
    values: &[toml::Value],
    haystack_len: usize,
) -> Result<ExpectedSpan, InventoryError> {
    if values.len() != 2 {
        return Err(InventoryError::new(
            "expected span does not have two offsets",
        ));
    }
    let start = decode_nonnegative(values.first(), "expected span start")?;
    let end = decode_nonnegative(values.get(1), "expected span end")?;
    if start > end || end > haystack_len {
        return Err(InventoryError::new(
            "expected span is out of haystack range",
        ));
    }
    Ok(ExpectedSpan { start, end })
}

fn decode_nonnegative(value: Option<&toml::Value>, field: &str) -> Result<usize, InventoryError> {
    let value = value
        .and_then(toml::Value::as_integer)
        .ok_or_else(|| InventoryError::new(format!("{field} is not an integer")))?;
    usize::try_from(value).map_err(|_| InventoryError::new(format!("{field} is negative")))
}

fn validate_candidate(candidate: &CandidateIdentity) -> Result<(), InventoryError> {
    if !is_commit_oid(&candidate.revision)
        || !is_commit_oid(&candidate.tree)
        || !candidate.tracked_and_untracked_worktree_clean
    {
        return Err(InventoryError::new("adapter candidate identity is invalid"));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn semantic_comparator_distinguishes_pass_and_mismatch() {
        let pass = compare(&SemanticValue::IsMatch(true), &SemanticValue::IsMatch(true));
        assert!(matches!(pass, AdapterDisposition::Pass { .. }));
        let mismatch = compare(
            &SemanticValue::IsMatch(true),
            &SemanticValue::IsMatch(false),
        );
        assert!(matches!(mismatch, AdapterDisposition::Mismatch { .. }));
    }

    #[test]
    fn byte_adapter_executes_literal_compile_match_and_limited_find() {
        let case = fixture_case(true, false, Some(1));
        let input = fixture_input(vec![ExpectedCaptures {
            pattern_id: 0,
            groups: vec![Some(ExpectedSpan { start: 1, end: 2 })],
        }]);
        assert!(matches!(
            execute_bytes_compile(&case, &input),
            AdapterDisposition::Pass { .. }
        ));
        assert!(matches!(
            execute_bytes_is_match(&case, &input),
            AdapterDisposition::Pass { .. }
        ));
        assert!(matches!(
            execute_bytes_find(&case, &input),
            AdapterDisposition::Pass { .. }
        ));
    }

    #[test]
    fn text_slice_and_complete_match_iteration_execute_with_utf8_guarded_boundaries() {
        let case = fixture_case(true, false, None);
        let input = fixture_input(vec![ExpectedCaptures {
            pattern_id: 0,
            groups: vec![Some(ExpectedSpan { start: 1, end: 2 })],
        }]);
        assert!(matches!(
            execute_bytes_find(&case, &input),
            AdapterDisposition::Pass { .. }
        ));
        assert_eq!(
            surface_applicability(AdapterSurface::RustTextCompile, &case, &input),
            Err(NotApplicableReason::ProfileCannotRepresentUtf8Mode)
        );

        let text_case = fixture_case(true, true, None);
        assert!(matches!(
            execute_case(AdapterSurface::RustTextCompile, &text_case, &input),
            AdapterDisposition::Pass { .. }
        ));
        assert!(matches!(
            execute_case(AdapterSurface::RustTextCapturesIter, &text_case, &input),
            AdapterDisposition::Pass { .. }
        ));
        assert!(matches!(
            execute_case(AdapterSurface::RustBytesCapturesIter, &case, &input),
            AdapterDisposition::Pass { .. }
        ));

        let text_limited = fixture_case(true, true, Some(1));
        assert!(matches!(
            execute_case(AdapterSurface::RustTextIsMatch, &text_limited, &input),
            AdapterDisposition::Pass { .. }
        ));
        assert!(matches!(
            execute_case(AdapterSurface::RustTextFindIter, &text_limited, &input),
            AdapterDisposition::Pass { .. }
        ));

        let mut nonfinite = input.clone();
        nonfinite.patterns = vec!["a+".to_owned()];
        assert!(matches!(
            execute_case(AdapterSurface::RustTextCompile, &text_case, &nonfinite),
            AdapterDisposition::Pass { .. }
        ));
        assert!(matches!(
            execute_case(AdapterSurface::RustTextIsMatch, &text_case, &nonfinite),
            AdapterDisposition::Pass { .. }
        ));

        let mut guarded = input.clone();
        guarded.patterns = vec![r"\B".to_owned()];
        guarded.expected = vec![ExpectedCaptures {
            pattern_id: 0,
            groups: vec![Some(ExpectedSpan { start: 1, end: 1 })],
        }];
        assert!(matches!(
            execute_case(AdapterSurface::RustTextCompile, &text_case, &guarded),
            AdapterDisposition::Pass { .. }
        ));
        assert!(matches!(
            execute_case(AdapterSurface::RustTextIsMatch, &text_case, &guarded),
            AdapterDisposition::Pass { .. }
        ));
        assert!(matches!(
            execute_case(AdapterSurface::RustTextFindIter, &text_case, &guarded),
            AdapterDisposition::Pass { .. }
        ));
    }

    #[test]
    fn pinned_captures_wrong_order_executes_on_text_capture_surface() {
        let mut case = fixture_case(true, true, None);
        case.id = "regression/captures-wrong-order".to_owned();
        case.upstream_name = case.id.clone();
        case.source_file = "regression.toml".to_owned();
        case.source_ordinal = 77;
        case.unicode = true;
        case.maximum_expected_capture_slots = 3;
        let input = ExecutableCase {
            id: case.id.clone(),
            patterns: vec!["(a){0}(a)".to_owned()],
            haystack: b"a".to_vec(),
            bounds: SearchBounds { start: 0, end: 1 },
            line_terminator: b'\n',
            expected: vec![ExpectedCaptures {
                pattern_id: 0,
                groups: vec![
                    Some(ExpectedSpan { start: 0, end: 1 }),
                    None,
                    Some(ExpectedSpan { start: 0, end: 1 }),
                ],
            }],
        };
        assert!(matches!(
            execute_case(AdapterSurface::RustTextCapturesIter, &case, &input),
            AdapterDisposition::Pass { .. }
        ));
    }

    #[test]
    fn native_capture_envelope_and_capture_free_fallback_remain_distinct() {
        let mut case = fixture_case(true, true, None);
        case.unicode = true;
        case.maximum_expected_capture_slots = 1;

        let mut counted = fixture_input(vec![ExpectedCaptures {
            pattern_id: 0,
            groups: vec![Some(ExpectedSpan { start: 0, end: 1 })],
        }]);
        counted.patterns = vec![r"^.{1,2500}".to_owned()];
        counted.haystack = b"a".to_vec();
        counted.bounds.end = counted.haystack.len();
        assert!(matches!(
            build_text_captures(&case, &counted),
            TextCaptureBuildAttempt::Built(_)
        ));
        assert!(matches!(
            execute_case(AdapterSurface::RustTextCapturesIter, &case, &counted),
            AdapterDisposition::Pass { .. }
        ));

        let mut unicode = fixture_input(
            [0_usize, 50, 100]
                .into_iter()
                .map(|start| ExpectedCaptures {
                    pattern_id: 0,
                    groups: vec![Some(ExpectedSpan {
                        start,
                        end: start + 50,
                    })],
                })
                .collect(),
        );
        unicode.patterns = vec![r"\pL{50}".to_owned()];
        unicode.haystack = b"abcdefghijklmnopqrstuvwxyabcdefghijklmnopqrstuvwxyabcdefghijklmnopqrstuvwxyabcdefghijklmnopqrstuvwxyabcdefghijklmnopqrstuvwxyabcdefghijklmnopqrstuvwxyZZ".to_vec();
        unicode.bounds.end = unicode.haystack.len();
        assert!(matches!(
            build_text_captures(&case, &unicode),
            TextCaptureBuildAttempt::Built(_)
        ));
        assert!(matches!(
            execute_case(AdapterSurface::RustTextCapturesIter, &case, &unicode),
            AdapterDisposition::Pass { .. }
        ));

        let mut explicit_direct = counted.clone();
        explicit_direct.patterns = vec![r"(.{1,2500})".to_owned()];
        explicit_direct.expected[0]
            .groups
            .push(Some(ExpectedSpan { start: 0, end: 1 }));
        case.maximum_expected_capture_slots = 2;
        assert!(matches!(
            build_text_captures(&case, &explicit_direct),
            TextCaptureBuildAttempt::Built(_)
        ));
        assert!(matches!(
            execute_case(
                AdapterSurface::RustTextCapturesIter,
                &case,
                &explicit_direct
            ),
            AdapterDisposition::Pass { .. }
        ));

        let mut fallback = counted;
        fallback.patterns = vec![r"^.{1,2501}".to_owned()];
        case.maximum_expected_capture_slots = 1;
        assert!(matches!(
            build_text_captures(&case, &fallback),
            TextCaptureBuildAttempt::Unsupported(_)
        ));
        assert!(matches!(
            execute_case(AdapterSurface::RustTextCapturesIter, &case, &fallback),
            AdapterDisposition::Pass { .. }
        ));

        let mut explicit_fallback = fallback;
        explicit_fallback.patterns = vec![r"(.{1,2501})".to_owned()];
        explicit_fallback.expected[0]
            .groups
            .push(Some(ExpectedSpan { start: 0, end: 1 }));
        case.maximum_expected_capture_slots = 2;
        assert!(matches!(
            build_text_captures(&case, &explicit_fallback),
            TextCaptureBuildAttempt::Unsupported(_)
        ));
        assert!(matches!(
            execute_case(
                AdapterSurface::RustTextCapturesIter,
                &case,
                &explicit_fallback
            ),
            AdapterDisposition::Unsupported { .. }
        ));
    }

    #[test]
    fn text_set_surfaces_compile_match_and_deduplicate_pattern_ids() {
        let mut case = fixture_case(true, true, None);
        case.pattern_count = 2;
        case.match_kind = MatchKind::All;
        case.search_kind = SearchKind::Overlapping;
        case.unicode = true;
        let input = ExecutableCase {
            id: case.id.clone(),
            patterns: vec!["a".to_owned(), "a|é".to_owned()],
            haystack: "baé".as_bytes().to_vec(),
            bounds: SearchBounds { start: 0, end: 4 },
            line_terminator: b'\n',
            expected: vec![
                ExpectedCaptures {
                    pattern_id: 0,
                    groups: vec![Some(ExpectedSpan { start: 1, end: 2 })],
                },
                ExpectedCaptures {
                    pattern_id: 1,
                    groups: vec![Some(ExpectedSpan { start: 1, end: 2 })],
                },
                ExpectedCaptures {
                    pattern_id: 1,
                    groups: vec![Some(ExpectedSpan { start: 2, end: 4 })],
                },
            ],
        };
        assert!(matches!(
            execute_case(AdapterSurface::RustTextSetCompile, &case, &input),
            AdapterDisposition::Pass { .. }
        ));
        assert!(matches!(
            execute_case(AdapterSurface::RustTextSetIsMatch, &case, &input),
            AdapterDisposition::Pass { .. }
        ));
        assert!(matches!(
            execute_case(AdapterSurface::RustTextSetWhich, &case, &input),
            AdapterDisposition::Pass { .. }
        ));
        assert_eq!(expected_pattern_ids(&input), vec![0, 1]);
    }

    #[test]
    fn bytes_set_surfaces_preserve_arbitrary_bytes_and_ascending_pattern_ids() {
        let mut case = fixture_case(true, false, None);
        case.pattern_count = 3;
        case.match_kind = MatchKind::All;
        case.search_kind = SearchKind::Overlapping;
        case.unicode = false;
        let input = ExecutableCase {
            id: case.id.clone(),
            patterns: vec![String::new(), r"(?-u:\xFF)".to_owned(), String::new()],
            haystack: vec![0xFF],
            bounds: SearchBounds { start: 0, end: 1 },
            line_terminator: b'\n',
            expected: vec![
                ExpectedCaptures {
                    pattern_id: 2,
                    groups: vec![Some(ExpectedSpan { start: 1, end: 1 })],
                },
                ExpectedCaptures {
                    pattern_id: 0,
                    groups: vec![Some(ExpectedSpan { start: 0, end: 0 })],
                },
                ExpectedCaptures {
                    pattern_id: 1,
                    groups: vec![Some(ExpectedSpan { start: 0, end: 1 })],
                },
            ],
        };
        assert!(matches!(
            execute_case(AdapterSurface::RustBytesSetCompile, &case, &input),
            AdapterDisposition::Pass { .. }
        ));
        assert!(matches!(
            execute_case(AdapterSurface::RustBytesSetIsMatch, &case, &input),
            AdapterDisposition::Pass { .. }
        ));
        assert!(matches!(
            execute_case(AdapterSurface::RustBytesSetWhich, &case, &input),
            AdapterDisposition::Pass { .. }
        ));
        assert_eq!(expected_pattern_ids(&input), vec![0, 1, 2]);
    }

    #[test]
    fn bytes_set_compile_rejection_is_compared_not_hidden() {
        let mut case = fixture_case(false, false, None);
        case.pattern_count = 2;
        case.match_kind = MatchKind::All;
        case.search_kind = SearchKind::Overlapping;
        let mut input = fixture_input(Vec::new());
        input.patterns = vec!["valid".to_owned(), "(".to_owned()];
        input.bounds.end = input.haystack.len();
        assert!(matches!(
            execute_case(AdapterSurface::RustBytesSetCompile, &case, &input),
            AdapterDisposition::Pass { .. }
        ));
    }

    #[test]
    fn set_compile_is_selection_policy_invariant_for_every_pattern_count() {
        let mut case = fixture_case(true, true, None);
        case.pattern_count = 2;
        let mut input = fixture_input(Vec::new());
        input.patterns = vec!["a".to_owned(), "b".to_owned()];

        for surface in [
            AdapterSurface::RustTextSetCompile,
            AdapterSurface::RustBytesSetCompile,
        ] {
            assert_eq!(surface_applicability(surface, &case, &input), Ok(()));
            assert!(matches!(
                execute_case(surface, &case, &input),
                AdapterDisposition::Pass { .. }
            ));
        }

        case.search_kind = SearchKind::Overlapping;
        case.match_kind = MatchKind::LeftmostFirst;
        for surface in [
            AdapterSurface::RustTextSetCompile,
            AdapterSurface::RustBytesSetCompile,
        ] {
            assert_eq!(surface_applicability(surface, &case, &input), Ok(()));
            assert!(matches!(
                execute_case(surface, &case, &input),
                AdapterDisposition::Pass { .. }
            ));
        }

        case.search_kind = SearchKind::Leftmost;
        case.utf8 = false;
        assert_eq!(
            surface_applicability(AdapterSurface::RustBytesSetCompile, &case, &input),
            Ok(())
        );
        assert_eq!(
            surface_applicability(AdapterSurface::RustTextSetCompile, &case, &input),
            Err(NotApplicableReason::ProfileCannotRepresentSearchMode)
        );

        case.utf8 = true;
        case.pattern_count = 0;
        input.patterns.clear();
        for surface in [
            AdapterSurface::RustTextSetCompile,
            AdapterSurface::RustBytesSetCompile,
        ] {
            assert!(matches!(
                execute_case(surface, &case, &input),
                AdapterDisposition::Pass { .. }
            ));
        }

        case.compiles = false;
        case.pattern_count = 2;
        input.patterns = vec!["a".to_owned(), "(".to_owned()];
        for surface in [
            AdapterSurface::RustTextSetCompile,
            AdapterSurface::RustBytesSetCompile,
        ] {
            assert!(matches!(
                execute_case(surface, &case, &input),
                AdapterDisposition::Pass { .. }
            ));
        }
    }

    #[test]
    fn utf8_bytes_set_compile_and_invariant_observations_delegate_to_text_proof() {
        let mut case = fixture_case(true, true, None);
        case.pattern_count = 2;
        case.match_kind = MatchKind::All;
        case.search_kind = SearchKind::Overlapping;
        case.unicode = true;
        let mut input = fixture_input(Vec::new());
        input.patterns = vec!["a".to_owned(), "é+".to_owned()];
        input.haystack = "aé".as_bytes().to_vec();
        input.bounds.end = input.haystack.len();
        input.expected = vec![
            ExpectedCaptures {
                pattern_id: 0,
                groups: vec![Some(ExpectedSpan { start: 0, end: 1 })],
            },
            ExpectedCaptures {
                pattern_id: 1,
                groups: vec![Some(ExpectedSpan { start: 1, end: 3 })],
            },
        ];

        assert_eq!(
            surface_applicability(AdapterSurface::RustBytesSetCompile, &case, &input),
            Ok(())
        );
        assert!(matches!(
            execute_case(AdapterSurface::RustBytesSetCompile, &case, &input),
            AdapterDisposition::Pass { .. }
        ));
        assert_eq!(
            surface_applicability(AdapterSurface::RustBytesSetIsMatch, &case, &input),
            Ok(())
        );
        assert!(matches!(
            execute_case(AdapterSurface::RustBytesSetIsMatch, &case, &input),
            AdapterDisposition::Pass { .. }
        ));
        assert_eq!(
            surface_applicability(AdapterSurface::RustBytesSetWhich, &case, &input),
            Ok(())
        );
        assert!(matches!(
            execute_case(AdapterSurface::RustBytesSetWhich, &case, &input),
            AdapterDisposition::Pass { .. }
        ));

        let mut selection_sensitive = case.clone();
        selection_sensitive.match_kind = MatchKind::LeftmostFirst;
        let mut selected_input = input.clone();
        selected_input.expected.truncate(1);
        assert_eq!(
            surface_applicability(
                AdapterSurface::RustBytesSetWhich,
                &selection_sensitive,
                &selected_input,
            ),
            Ok(())
        );
        assert!(matches!(
            execute_case(
                AdapterSurface::RustBytesSetWhich,
                &selection_sensitive,
                &selected_input,
            ),
            AdapterDisposition::Pass { .. }
        ));

        let mut anchored = case.clone();
        anchored.anchored = true;
        assert_eq!(
            surface_applicability(AdapterSurface::RustBytesSetWhich, &anchored, &input),
            Err(NotApplicableReason::ProfileCannotRepresentAnchoring)
        );

        let mut bounded = input.clone();
        bounded.bounds.start = 1;
        assert_eq!(
            surface_applicability(AdapterSurface::RustBytesSetWhich, &case, &bounded),
            Err(NotApplicableReason::ProfileCannotRepresentBounds)
        );

        let mut limited = case.clone();
        limited.match_limit = Some(0);
        assert_eq!(
            surface_applicability(AdapterSurface::RustBytesSetWhich, &limited, &input),
            Err(NotApplicableReason::ProfileCannotRepresentUtf8Mode)
        );

        let mut invalid = input.clone();
        invalid.haystack = vec![0xFF];
        invalid.bounds.end = 1;
        assert_eq!(
            surface_applicability(AdapterSurface::RustBytesSetWhich, &case, &invalid),
            Err(NotApplicableReason::ProfileCannotRepresentUtf8Mode)
        );

        case.compiles = false;
        input.patterns = vec!["a".to_owned(), "(".to_owned()];
        assert!(matches!(
            execute_case(AdapterSurface::RustBytesSetCompile, &case, &input),
            AdapterDisposition::Pass { .. }
        ));
    }

    #[test]
    fn text_set_scalar_guarded_ascii_assertions_execute() {
        let mut case = fixture_case(true, true, None);
        case.match_kind = MatchKind::All;
        case.search_kind = SearchKind::Overlapping;
        case.unicode = true;
        let mut input = fixture_input(vec![ExpectedCaptures {
            pattern_id: 0,
            groups: vec![Some(ExpectedSpan { start: 1, end: 1 })],
        }]);
        input.patterns = vec![r"(?-u:\B)".to_owned()];
        assert!(matches!(
            execute_case(AdapterSurface::RustTextSetCompile, &case, &input),
            AdapterDisposition::Pass { .. }
        ));
        assert!(matches!(
            execute_case(AdapterSurface::RustTextSetIsMatch, &case, &input),
            AdapterDisposition::Pass { .. }
        ));
        assert!(matches!(
            execute_case(AdapterSurface::RustTextSetWhich, &case, &input),
            AdapterDisposition::Pass { .. }
        ));
    }

    #[test]
    fn one_pattern_set_observations_are_independent_of_selection_policy() {
        let text_case = fixture_case(true, true, None);
        let text_input = fixture_input(vec![ExpectedCaptures {
            pattern_id: 0,
            groups: vec![Some(ExpectedSpan { start: 1, end: 2 })],
        }]);
        assert_eq!(
            surface_applicability(AdapterSurface::RustTextSetCompile, &text_case, &text_input),
            Ok(())
        );
        assert!(matches!(
            execute_case(AdapterSurface::RustTextSetCompile, &text_case, &text_input,),
            AdapterDisposition::Pass { .. }
        ));
        assert_eq!(
            surface_applicability(AdapterSurface::RustTextSetIsMatch, &text_case, &text_input),
            Ok(())
        );
        assert!(matches!(
            execute_case(AdapterSurface::RustTextSetIsMatch, &text_case, &text_input),
            AdapterDisposition::Pass { .. }
        ));
        assert!(matches!(
            execute_case(AdapterSurface::RustTextSetWhich, &text_case, &text_input),
            AdapterDisposition::Pass { .. }
        ));
        assert_eq!(
            surface_applicability(AdapterSurface::RustBytesSetCompile, &text_case, &text_input),
            Ok(())
        );
        assert!(matches!(
            execute_case(AdapterSurface::RustBytesSetCompile, &text_case, &text_input,),
            AdapterDisposition::Pass { .. }
        ));

        let bytes_case = fixture_case(true, false, None);
        assert!(matches!(
            execute_case(
                AdapterSurface::RustBytesSetCompile,
                &bytes_case,
                &text_input,
            ),
            AdapterDisposition::Pass { .. }
        ));
        assert!(matches!(
            execute_case(
                AdapterSurface::RustBytesSetIsMatch,
                &bytes_case,
                &text_input,
            ),
            AdapterDisposition::Pass { .. }
        ));
        assert!(matches!(
            execute_case(AdapterSurface::RustBytesSetWhich, &bytes_case, &text_input,),
            AdapterDisposition::Pass { .. }
        ));

        // UTF-8 bytes observations use the same exact text-equivalence proof as
        // the already-qualified bytes is-match facade.
        assert!(matches!(
            execute_case(AdapterSurface::RustBytesSetIsMatch, &text_case, &text_input,),
            AdapterDisposition::Pass { .. }
        ));
        assert!(matches!(
            execute_case(AdapterSurface::RustBytesSetWhich, &text_case, &text_input,),
            AdapterDisposition::Pass { .. }
        ));

        let mut no_match = text_input.clone();
        no_match.patterns = vec!["z".to_owned()];
        no_match.expected.clear();
        assert!(matches!(
            execute_case(AdapterSurface::RustTextSetIsMatch, &text_case, &no_match,),
            AdapterDisposition::Pass { .. }
        ));
        assert!(matches!(
            execute_case(AdapterSurface::RustTextSetWhich, &text_case, &no_match,),
            AdapterDisposition::Pass { .. }
        ));
    }

    #[test]
    fn singleton_set_delegation_preserves_anchoring_and_bounds() {
        let text_case = fixture_case(true, true, None);
        let text_input = fixture_input(vec![ExpectedCaptures {
            pattern_id: 0,
            groups: vec![Some(ExpectedSpan { start: 1, end: 2 })],
        }]);
        let mut anchored = text_case.clone();
        anchored.anchored = true;
        assert_eq!(
            surface_applicability(AdapterSurface::RustTextSetIsMatch, &anchored, &text_input),
            Ok(())
        );
        let mut anchored_input = text_input.clone();
        anchored_input.expected.clear();
        assert!(matches!(
            execute_case(AdapterSurface::RustTextSetWhich, &anchored, &anchored_input,),
            AdapterDisposition::Pass { .. }
        ));

        let mut bounded = text_input;
        bounded.bounds.start = 1;
        assert_eq!(
            surface_applicability(AdapterSurface::RustTextSetWhich, &text_case, &bounded),
            Ok(())
        );
        assert!(matches!(
            execute_case(AdapterSurface::RustTextSetWhich, &text_case, &bounded),
            AdapterDisposition::Pass { .. }
        ));
    }

    #[test]
    fn singleton_set_domain_is_policy_invariant_but_keeps_strict_guards() {
        let expected = vec![ExpectedCaptures {
            pattern_id: 0,
            groups: vec![Some(ExpectedSpan { start: 1, end: 2 })],
        }];
        for (search_kind, match_kind) in [
            (SearchKind::Earliest, MatchKind::LeftmostFirst),
            (SearchKind::Leftmost, MatchKind::All),
            (SearchKind::Overlapping, MatchKind::LeftmostFirst),
            (SearchKind::Overlapping, MatchKind::All),
        ] {
            let mut case = fixture_case(true, true, None);
            case.search_kind = search_kind;
            case.match_kind = match_kind;
            case.anchored = true;
            case.bounded_search = true;
            let mut input = fixture_input(expected.clone());
            input.bounds.start = 1;
            for surface in [
                AdapterSurface::RustTextSetIsMatch,
                AdapterSurface::RustTextSetWhich,
                AdapterSurface::RustBytesSetIsMatch,
                AdapterSurface::RustBytesSetWhich,
            ] {
                assert_eq!(surface_applicability(surface, &case, &input), Ok(()));
                assert!(matches!(
                    execute_case(surface, &case, &input),
                    AdapterDisposition::Pass { .. }
                ));
            }
        }

        let mut bytes_case = fixture_case(true, false, None);
        bytes_case.search_kind = SearchKind::Overlapping;
        bytes_case.match_kind = MatchKind::All;
        bytes_case.anchored = true;
        bytes_case.bounded_search = true;
        let mut bytes_input = fixture_input(expected.clone());
        bytes_input.bounds.start = 1;
        for surface in [
            AdapterSurface::RustBytesSetIsMatch,
            AdapterSurface::RustBytesSetWhich,
        ] {
            assert_eq!(
                surface_applicability(surface, &bytes_case, &bytes_input),
                Ok(())
            );
            assert!(matches!(
                execute_case(surface, &bytes_case, &bytes_input),
                AdapterDisposition::Pass { .. }
            ));
        }
    }

    #[test]
    fn singleton_set_domain_keeps_strict_guards() {
        let expected = vec![ExpectedCaptures {
            pattern_id: 0,
            groups: vec![Some(ExpectedSpan { start: 1, end: 2 })],
        }];
        let mut zero_limit = fixture_case(true, true, Some(0));
        zero_limit.search_kind = SearchKind::Overlapping;
        zero_limit.match_kind = MatchKind::All;
        let zero_input = fixture_input(Vec::new());
        for surface in [
            AdapterSurface::RustTextSetIsMatch,
            AdapterSurface::RustTextSetWhich,
            AdapterSurface::RustBytesSetIsMatch,
            AdapterSurface::RustBytesSetWhich,
        ] {
            assert_eq!(
                surface_applicability(surface, &zero_limit, &zero_input),
                Err(NotApplicableReason::ProfileCannotRepresentBounds)
            );
            assert!(matches!(
                execute_case(surface, &zero_limit, &zero_input),
                AdapterDisposition::NotApplicable {
                    reason: NotApplicableReason::ProfileCannotRepresentBounds
                }
            ));
        }

        let mut invalid_case = fixture_case(true, true, None);
        invalid_case.search_kind = SearchKind::Overlapping;
        invalid_case.match_kind = MatchKind::All;
        invalid_case.anchored = true;
        let mut invalid_input = fixture_input(Vec::new());
        invalid_input.haystack = vec![0xFF];
        invalid_input.bounds = SearchBounds { start: 0, end: 1 };
        for surface in [
            AdapterSurface::RustBytesSetIsMatch,
            AdapterSurface::RustBytesSetWhich,
        ] {
            assert_eq!(
                surface_applicability(surface, &invalid_case, &invalid_input),
                Err(NotApplicableReason::InvalidUtf8Haystack)
            );
        }

        let mut multiple_case = fixture_case(true, true, None);
        multiple_case.pattern_count = 2;
        multiple_case.search_kind = SearchKind::Overlapping;
        multiple_case.match_kind = MatchKind::All;
        multiple_case.anchored = true;
        let mut multiple_input = fixture_input(expected);
        multiple_input.patterns.push("b".to_owned());
        for surface in [
            AdapterSurface::RustTextSetIsMatch,
            AdapterSurface::RustTextSetWhich,
            AdapterSurface::RustBytesSetIsMatch,
            AdapterSurface::RustBytesSetWhich,
        ] {
            assert_eq!(
                surface_applicability(surface, &multiple_case, &multiple_input),
                Err(NotApplicableReason::ProfileCannotRepresentAnchoring)
            );
        }
    }

    #[test]
    fn set_delegation_rejects_unproved_observations_not_compilation() {
        let text_case = fixture_case(true, true, None);
        let text_input = fixture_input(vec![ExpectedCaptures {
            pattern_id: 0,
            groups: vec![Some(ExpectedSpan { start: 1, end: 2 })],
        }]);
        let mut multiple = text_input.clone();
        multiple.patterns.push("b".to_owned());
        let mut multiple_case = text_case.clone();
        multiple_case.pattern_count = 2;
        assert_eq!(
            surface_applicability(
                AdapterSurface::RustTextSetCompile,
                &multiple_case,
                &multiple,
            ),
            Ok(())
        );
        assert!(matches!(
            execute_case(
                AdapterSurface::RustTextSetCompile,
                &multiple_case,
                &multiple,
            ),
            AdapterDisposition::Pass { .. }
        ));

        let mut zero = text_input.clone();
        zero.patterns.clear();
        zero.expected.clear();
        assert_eq!(
            surface_applicability(AdapterSurface::RustTextSetIsMatch, &text_case, &zero),
            Ok(())
        );
        assert!(matches!(
            execute_case(AdapterSurface::RustTextSetIsMatch, &text_case, &zero),
            AdapterDisposition::Pass { .. }
        ));
        assert!(matches!(
            execute_case(AdapterSurface::RustTextSetWhich, &text_case, &zero),
            AdapterDisposition::Pass { .. }
        ));

        let rejected_case = fixture_case(false, true, None);
        let mut rejected = text_input.clone();
        rejected.patterns = vec!["(".to_owned()];
        assert!(matches!(
            execute_case(
                AdapterSurface::RustTextSetCompile,
                &rejected_case,
                &rejected,
            ),
            AdapterDisposition::Pass { .. }
        ));
        assert_eq!(
            surface_applicability(
                AdapterSurface::RustTextSetIsMatch,
                &rejected_case,
                &text_input,
            ),
            Err(NotApplicableReason::CompileOnlyCase)
        );

        let mut invalid_text = text_input;
        invalid_text.haystack = vec![0xFF];
        invalid_text.bounds = SearchBounds { start: 0, end: 1 };
        assert_eq!(
            surface_applicability(
                AdapterSurface::RustTextSetCompile,
                &text_case,
                &invalid_text,
            ),
            Err(NotApplicableReason::InvalidUtf8Haystack)
        );
        assert_eq!(
            surface_applicability(AdapterSurface::RustBytesSetWhich, &text_case, &invalid_text,),
            Err(NotApplicableReason::InvalidUtf8Haystack)
        );
    }

    #[test]
    fn overlapping_leftmost_first_multi_which_selects_the_ordered_union_winner() {
        let mut case = fixture_case(true, true, None);
        case.pattern_count = 2;
        case.search_kind = SearchKind::Overlapping;
        let input = ExecutableCase {
            id: case.id.clone(),
            patterns: vec!["foo".to_owned(), "oo".to_owned()],
            haystack: b"foo".to_vec(),
            bounds: SearchBounds { start: 0, end: 3 },
            line_terminator: b'\n',
            expected: vec![ExpectedCaptures {
                pattern_id: 0,
                groups: vec![Some(ExpectedSpan { start: 0, end: 3 })],
            }],
        };
        for surface in [
            AdapterSurface::RustTextSetIsMatch,
            AdapterSurface::RustBytesSetIsMatch,
        ] {
            assert_eq!(surface_applicability(surface, &case, &input), Ok(()));
            assert!(matches!(
                execute_case(surface, &case, &input),
                AdapterDisposition::Pass { .. }
            ));
        }
        for surface in [
            AdapterSurface::RustTextSetWhich,
            AdapterSurface::RustBytesSetWhich,
        ] {
            assert_eq!(surface_applicability(surface, &case, &input), Ok(()));
            assert!(matches!(
                execute_case(surface, &case, &input),
                AdapterDisposition::Pass { .. }
            ));
        }
    }

    #[test]
    fn leftmost_first_multi_which_preserves_priority_iteration_and_empty_progress() {
        let mut case = fixture_case(true, true, None);
        case.pattern_count = 2;
        let input = ExecutableCase {
            id: case.id.clone(),
            patterns: vec!["a".to_owned(), String::new()],
            haystack: b"abc".to_vec(),
            bounds: SearchBounds { start: 0, end: 3 },
            line_terminator: b'\n',
            expected: vec![
                ExpectedCaptures {
                    pattern_id: 0,
                    groups: vec![Some(ExpectedSpan { start: 0, end: 1 })],
                },
                ExpectedCaptures {
                    pattern_id: 1,
                    groups: vec![Some(ExpectedSpan { start: 2, end: 2 })],
                },
            ],
        };
        for surface in [
            AdapterSurface::RustTextSetWhich,
            AdapterSurface::RustBytesSetWhich,
        ] {
            assert_eq!(surface_applicability(surface, &case, &input), Ok(()));
            assert!(matches!(
                execute_case(surface, &case, &input),
                AdapterDisposition::Pass { .. }
            ));
        }

        let mut arbitrary_bytes_case = case;
        arbitrary_bytes_case.utf8 = false;
        assert_eq!(
            surface_applicability(
                AdapterSurface::RustTextSetWhich,
                &arbitrary_bytes_case,
                &input,
            ),
            Err(NotApplicableReason::ProfileCannotRepresentSearchMode)
        );
        assert!(matches!(
            execute_case(
                AdapterSurface::RustBytesSetWhich,
                &arbitrary_bytes_case,
                &input,
            ),
            AdapterDisposition::Pass { .. }
        ));
    }

    #[test]
    fn leftmost_all_multi_which_selects_the_last_exact_literal_match() {
        let mut case = fixture_case(true, true, None);
        case.pattern_count = 2;
        case.match_kind = MatchKind::All;
        let input = ExecutableCase {
            id: case.id.clone(),
            patterns: vec!["foo".to_owned(), "foobar".to_owned()],
            haystack: b"foobar".to_vec(),
            bounds: SearchBounds { start: 0, end: 6 },
            line_terminator: b'\n',
            expected: vec![ExpectedCaptures {
                pattern_id: 1,
                groups: vec![Some(ExpectedSpan { start: 0, end: 6 })],
            }],
        };
        for surface in [
            AdapterSurface::RustTextSetWhich,
            AdapterSurface::RustBytesSetWhich,
        ] {
            assert_eq!(surface_applicability(surface, &case, &input), Ok(()));
            assert!(matches!(
                execute_case(surface, &case, &input),
                AdapterDisposition::Pass { .. }
            ));
        }

        let mut unsupported = input;
        unsupported.patterns = vec!["f+".to_owned(), "foobar".to_owned()];
        assert!(matches!(
            execute_case(AdapterSurface::RustTextSetWhich, &case, &unsupported),
            AdapterDisposition::Unsupported { .. }
        ));
    }

    #[test]
    fn leftmost_all_multi_which_preserves_declaration_priority_at_equal_end() {
        let fixtures = [
            (
                "duplicate-nonempty",
                vec!["a".to_owned(), "a".to_owned()],
                b"a".to_vec(),
                1,
            ),
            (
                "duplicate-empty",
                vec![String::new(), String::new()],
                Vec::new(),
                0,
            ),
        ];
        for (name, patterns, haystack, expected_end) in fixtures {
            let mut text_case = fixture_case(true, true, None);
            text_case.id = format!("fixture/{name}");
            text_case.upstream_name.clone_from(&text_case.id);
            text_case.pattern_count = patterns.len();
            text_case.match_kind = MatchKind::All;
            let input = ExecutableCase {
                id: text_case.id.clone(),
                patterns,
                bounds: SearchBounds {
                    start: 0,
                    end: haystack.len(),
                },
                haystack,
                line_terminator: b'\n',
                expected: vec![ExpectedCaptures {
                    pattern_id: 0,
                    groups: vec![Some(ExpectedSpan {
                        start: 0,
                        end: expected_end,
                    })],
                }],
            };

            assert_eq!(
                surface_applicability(AdapterSurface::RustTextSetWhich, &text_case, &input),
                Ok(())
            );
            assert!(
                matches!(
                    execute_case(AdapterSurface::RustTextSetWhich, &text_case, &input),
                    AdapterDisposition::Pass { .. }
                ),
                "text selector lost declaration priority for {name}"
            );

            let mut bytes_case = text_case;
            bytes_case.utf8 = false;
            assert_eq!(
                surface_applicability(AdapterSurface::RustBytesSetWhich, &bytes_case, &input),
                Ok(())
            );
            assert!(
                matches!(
                    execute_case(AdapterSurface::RustBytesSetWhich, &bytes_case, &input),
                    AdapterDisposition::Pass { .. }
                ),
                "byte selector lost declaration priority for {name}"
            );
        }
    }

    #[test]
    fn single_set_ids_are_selection_invariant_for_earliest_search() {
        let mut case = fixture_case(true, true, None);
        case.search_kind = SearchKind::Earliest;
        let input = fixture_input(vec![ExpectedCaptures {
            pattern_id: 0,
            groups: vec![Some(ExpectedSpan { start: 1, end: 2 })],
        }]);
        for surface in [
            AdapterSurface::RustTextSetIsMatch,
            AdapterSurface::RustTextSetWhich,
            AdapterSurface::RustBytesSetIsMatch,
            AdapterSurface::RustBytesSetWhich,
        ] {
            assert_eq!(surface_applicability(surface, &case, &input), Ok(()));
            assert!(matches!(
                execute_case(surface, &case, &input),
                AdapterDisposition::Pass { .. }
            ));
        }
    }

    #[test]
    fn utf8_bytes_set_observations_delegate_for_overlapping_all() {
        let mut case = fixture_case(true, true, None);
        case.search_kind = SearchKind::Overlapping;
        case.match_kind = MatchKind::All;
        let input = fixture_input(vec![ExpectedCaptures {
            pattern_id: 0,
            groups: vec![Some(ExpectedSpan { start: 1, end: 2 })],
        }]);
        for surface in [
            AdapterSurface::RustBytesSetIsMatch,
            AdapterSurface::RustBytesSetWhich,
        ] {
            assert_eq!(surface_applicability(surface, &case, &input), Ok(()));
            assert!(matches!(
                execute_case(surface, &case, &input),
                AdapterDisposition::Pass { .. }
            ));
        }

        let mut invalid = input;
        invalid.haystack = vec![0xFF];
        invalid.bounds.end = 1;
        assert_eq!(
            surface_applicability(AdapterSurface::RustBytesSetIsMatch, &case, &invalid),
            Err(NotApplicableReason::InvalidUtf8Haystack)
        );
    }

    #[test]
    fn selection_invariant_set_observations_reject_inexact_search_domains() {
        let mut case = fixture_case(true, true, None);
        case.search_kind = SearchKind::Earliest;
        let input = fixture_input(vec![ExpectedCaptures {
            pattern_id: 0,
            groups: vec![Some(ExpectedSpan { start: 1, end: 2 })],
        }]);

        let mut overlapping_multi = case.clone();
        overlapping_multi.search_kind = SearchKind::Overlapping;
        overlapping_multi.pattern_count = 2;
        let mut multiple = input.clone();
        multiple.patterns.push("b".to_owned());
        assert_eq!(
            selection_invariant_set_observation_applicability(
                AdapterSurface::RustBytesSetWhich,
                &overlapping_multi,
                &multiple,
                true,
            ),
            Err(NotApplicableReason::ProfileCannotRepresentSearchMode)
        );

        let mut anchored = case.clone();
        anchored.anchored = true;
        assert_eq!(
            selection_invariant_set_observation_applicability(
                AdapterSurface::RustTextSetIsMatch,
                &anchored,
                &input,
                true,
            ),
            Err(NotApplicableReason::ProfileCannotRepresentAnchoring)
        );

        let mut bounded = input.clone();
        bounded.bounds.start = 1;
        assert_eq!(
            selection_invariant_set_observation_applicability(
                AdapterSurface::RustTextSetIsMatch,
                &case,
                &bounded,
                true,
            ),
            Err(NotApplicableReason::ProfileCannotRepresentBounds)
        );

        let mut zero_limit = case.clone();
        zero_limit.match_limit = Some(0);
        assert_eq!(
            selection_invariant_set_observation_applicability(
                AdapterSurface::RustTextSetIsMatch,
                &zero_limit,
                &input,
                true,
            ),
            Err(NotApplicableReason::ProfileCannotRepresentBounds)
        );

        let mut invalid = input;
        invalid.haystack = vec![0xFF];
        invalid.bounds.end = 1;
        assert_eq!(
            surface_applicability(AdapterSurface::RustBytesSetIsMatch, &case, &invalid),
            Err(NotApplicableReason::InvalidUtf8Haystack)
        );
    }

    #[test]
    fn overlapping_all_enumerates_exact_spans_and_persistent_captures() {
        let span = |start, end| Some(ExpectedSpan { start, end });
        let mut case = fixture_case(true, true, None);
        case.search_kind = SearchKind::Overlapping;
        case.match_kind = MatchKind::All;
        case.unicode = true;
        case.maximum_expected_capture_slots = 2;
        let expected = [(0, 0), (1, 1), (0, 1), (2, 2), (1, 2), (0, 2)]
            .into_iter()
            .map(|(start, end)| ExpectedCaptures {
                pattern_id: 0,
                groups: vec![span(start, end), span(start, end)],
            })
            .collect();
        let input = ExecutableCase {
            id: case.id.clone(),
            patterns: vec!["(a*)".to_owned()],
            haystack: b"aa".to_vec(),
            bounds: SearchBounds { start: 0, end: 2 },
            line_terminator: b'\n',
            expected,
        };
        for surface in [
            AdapterSurface::RustTextFindIter,
            AdapterSurface::RustTextCapturesIter,
            AdapterSurface::RustBytesFindIter,
            AdapterSurface::RustBytesCapturesIter,
        ] {
            assert_eq!(surface_applicability(surface, &case, &input), Ok(()));
            let disposition = execute_case(surface, &case, &input);
            assert!(
                matches!(disposition, AdapterDisposition::Pass { .. }),
                "overlapping all failed on {surface:?}: {disposition:?}"
            );
        }
    }

    #[test]
    fn overlapping_leftmost_first_filters_forward_ends_before_reverse_starts() {
        let span = |start, end| Some(ExpectedSpan { start, end });
        let mut case = fixture_case(true, true, None);
        case.search_kind = SearchKind::Overlapping;
        case.unicode = true;
        case.maximum_expected_capture_slots = 2;
        let input = ExecutableCase {
            id: case.id.clone(),
            patterns: vec!["(abc|a)".to_owned()],
            haystack: b"zzabcazzaabc".to_vec(),
            bounds: SearchBounds { start: 0, end: 12 },
            line_terminator: b'\n',
            expected: vec![
                ExpectedCaptures {
                    pattern_id: 0,
                    groups: vec![span(2, 3), span(2, 3)],
                },
                ExpectedCaptures {
                    pattern_id: 0,
                    groups: vec![span(2, 5), span(2, 5)],
                },
            ],
        };
        for surface in [
            AdapterSurface::RustTextFindIter,
            AdapterSurface::RustTextCapturesIter,
            AdapterSurface::RustBytesFindIter,
            AdapterSurface::RustBytesCapturesIter,
        ] {
            let disposition = execute_case(surface, &case, &input);
            assert!(
                matches!(disposition, AdapterDisposition::Pass { .. }),
                "overlapping leftmost-first failed on {surface:?}: {disposition:?}"
            );
        }
    }

    #[test]
    fn overlapping_empty_matches_respect_text_scalars_and_byte_offsets() {
        let empty_at = |offset| ExpectedCaptures {
            pattern_id: 0,
            groups: vec![
                Some(ExpectedSpan {
                    start: offset,
                    end: offset,
                }),
                Some(ExpectedSpan {
                    start: offset,
                    end: offset,
                }),
            ],
        };
        let mut text_case = fixture_case(true, true, None);
        text_case.search_kind = SearchKind::Overlapping;
        text_case.match_kind = MatchKind::All;
        text_case.unicode = true;
        text_case.maximum_expected_capture_slots = 2;
        let text_input = ExecutableCase {
            id: text_case.id.clone(),
            patterns: vec!["()".to_owned()],
            haystack: "é".as_bytes().to_vec(),
            bounds: SearchBounds { start: 0, end: 2 },
            line_terminator: b'\n',
            expected: [0, 2].into_iter().map(empty_at).collect(),
        };
        for surface in [
            AdapterSurface::RustTextCapturesIter,
            AdapterSurface::RustBytesCapturesIter,
        ] {
            assert!(matches!(
                execute_case(surface, &text_case, &text_input),
                AdapterDisposition::Pass { .. }
            ));
        }

        let mut split_anchored_case = text_case.clone();
        split_anchored_case.anchored = true;
        split_anchored_case.bounded_search = true;
        let split_anchored_input = ExecutableCase {
            bounds: SearchBounds { start: 1, end: 2 },
            expected: Vec::new(),
            ..text_input.clone()
        };
        for surface in [
            AdapterSurface::RustTextFindIter,
            AdapterSurface::RustTextCapturesIter,
            AdapterSurface::RustBytesFindIter,
            AdapterSurface::RustBytesCapturesIter,
        ] {
            assert!(matches!(
                execute_case(surface, &split_anchored_case, &split_anchored_input),
                AdapterDisposition::Pass { .. }
            ));
        }

        let mut bytes_case = text_case;
        bytes_case.utf8 = false;
        let bytes_input = ExecutableCase {
            expected: [0, 1, 2].into_iter().map(empty_at).collect(),
            ..text_input
        };
        for surface in [
            AdapterSurface::RustBytesFindIter,
            AdapterSurface::RustBytesCapturesIter,
        ] {
            assert!(matches!(
                execute_case(surface, &bytes_case, &bytes_input),
                AdapterDisposition::Pass { .. }
            ));
        }
    }

    #[test]
    fn complete_iteration_matches_rust_empty_progress_and_limits() {
        let bytes = PortableBuilder::new("a|").build().unwrap();
        assert_eq!(
            collect_byte_matches(
                &bytes,
                b"abba",
                SearchBounds { start: 0, end: 4 },
                None,
                false,
            )
            .unwrap(),
            vec![
                ExpectedSpan { start: 0, end: 1 },
                ExpectedSpan { start: 2, end: 2 },
                ExpectedSpan { start: 3, end: 4 },
            ]
        );
        assert_eq!(
            collect_byte_matches(
                &bytes,
                b"abba",
                SearchBounds { start: 0, end: 4 },
                Some(1),
                false,
            )
            .unwrap(),
            vec![ExpectedSpan { start: 0, end: 1 }]
        );

        let empty_text = PortableTextBuilder::new("").build().unwrap();
        assert_eq!(
            collect_text_matches(
                &empty_text,
                "éa",
                SearchBounds { start: 0, end: 3 },
                None,
                false,
            )
            .unwrap(),
            vec![
                ExpectedSpan { start: 0, end: 0 },
                ExpectedSpan { start: 2, end: 2 },
                ExpectedSpan { start: 3, end: 3 },
            ]
        );
        let nullable_text = PortableTextBuilder::new("a*").build().unwrap();
        assert_eq!(
            collect_text_matches(
                &nullable_text,
                "ba",
                SearchBounds { start: 0, end: 2 },
                None,
                false,
            )
            .unwrap(),
            vec![
                ExpectedSpan { start: 0, end: 0 },
                ExpectedSpan { start: 1, end: 2 },
            ]
        );
        assert!(
            collect_text_matches(
                &nullable_text,
                "ba",
                SearchBounds { start: 0, end: 2 },
                Some(0),
                false,
            )
            .unwrap()
            .is_empty()
        );
    }

    #[test]
    fn anchored_iteration_keeps_only_the_contiguous_restart_prefix() {
        let bytes = PortableBuilder::new("a").build().unwrap();
        assert_eq!(
            collect_byte_matches(
                &bytes,
                b"aaba",
                SearchBounds { start: 0, end: 4 },
                None,
                true,
            )
            .unwrap(),
            vec![
                ExpectedSpan { start: 0, end: 1 },
                ExpectedSpan { start: 1, end: 2 },
            ]
        );
        let text = PortableTextBuilder::new("a").build().unwrap();
        assert_eq!(
            collect_text_matches(&text, "aaba", SearchBounds { start: 0, end: 4 }, None, true,)
                .unwrap(),
            vec![
                ExpectedSpan { start: 0, end: 1 },
                ExpectedSpan { start: 1, end: 2 },
            ]
        );

        let no_start = PortableBuilder::new(".c").build().unwrap();
        assert!(
            collect_byte_matches(
                &no_start,
                b"aabc",
                SearchBounds { start: 1, end: 4 },
                None,
                true,
            )
            .unwrap()
            .is_empty()
        );
    }

    #[test]
    fn anchored_empty_iteration_uses_raw_byte_restarts_before_utf8_gating() {
        let text = PortableTextBuilder::new("").build().unwrap();
        assert_eq!(
            collect_text_matches(&text, "a☃z", SearchBounds { start: 0, end: 5 }, None, true,)
                .unwrap(),
            vec![
                ExpectedSpan { start: 0, end: 0 },
                ExpectedSpan { start: 1, end: 1 },
            ]
        );
        assert!(
            collect_text_matches(&text, "𝛓", SearchBounds { start: 1, end: 3 }, None, true,)
                .unwrap()
                .is_empty()
        );
        let bytes = PortableBuilder::new("").build().unwrap();
        assert_eq!(
            collect_byte_matches(
                &bytes,
                "𝛓".as_bytes(),
                SearchBounds { start: 0, end: 4 },
                None,
                true,
            )
            .unwrap(),
            (0..=4)
                .map(|offset| ExpectedSpan {
                    start: offset,
                    end: offset,
                })
                .collect::<Vec<_>>()
        );
    }

    #[test]
    fn anchored_capture_filter_preserves_groups_and_stops_on_gap_or_utf8() {
        let record = |start, end| ExpectedCaptures {
            pattern_id: 0,
            groups: vec![
                Some(ExpectedSpan { start, end }),
                Some(ExpectedSpan { start, end }),
            ],
        };
        assert_eq!(
            anchored_capture_prefix(
                vec![record(0, 1), record(1, 2), record(3, 4)],
                SearchBounds { start: 0, end: 4 },
                None,
            )
            .unwrap(),
            vec![record(0, 1), record(1, 2)]
        );
        assert_eq!(
            anchored_capture_prefix(
                vec![record(0, 0), record(1, 1), record(4, 4)],
                SearchBounds { start: 0, end: 4 },
                Some("a☃"),
            )
            .unwrap(),
            vec![record(0, 0), record(1, 1)]
        );
    }

    #[test]
    fn anchored_single_surfaces_are_admitted_without_expected_value_dispatch() {
        let mut case = fixture_case(true, false, None);
        case.anchored = true;
        let input = ExecutableCase {
            id: case.id.clone(),
            patterns: vec![".c".to_owned()],
            haystack: b"abc".to_vec(),
            bounds: SearchBounds { start: 0, end: 3 },
            line_terminator: b'\n',
            expected: Vec::new(),
        };
        for surface in [
            AdapterSurface::RustBytesCompile,
            AdapterSurface::RustBytesIsMatch,
            AdapterSurface::RustBytesFindIter,
            AdapterSurface::RustBytesCapturesIter,
        ] {
            assert_eq!(surface_applicability(surface, &case, &input), Ok(()));
            assert!(matches!(
                execute_case(surface, &case, &input),
                AdapterDisposition::Pass { .. }
            ));
        }
        assert_eq!(
            surface_applicability(AdapterSurface::RustTextFindIter, &case, &input),
            Err(NotApplicableReason::ProfileCannotRepresentUtf8Mode)
        );
    }

    #[test]
    fn compile_and_match_existence_ignore_selection_policy_only() {
        let mut case = fixture_case(true, true, None);
        case.search_kind = SearchKind::Earliest;
        case.match_kind = MatchKind::All;
        let input = fixture_input(vec![ExpectedCaptures {
            pattern_id: 0,
            groups: vec![Some(ExpectedSpan { start: 1, end: 2 })],
        }]);
        for surface in [
            AdapterSurface::RustTextCompile,
            AdapterSurface::RustTextIsMatch,
            AdapterSurface::RustBytesCompile,
            AdapterSurface::RustBytesIsMatch,
        ] {
            assert_eq!(surface_applicability(surface, &case, &input), Ok(()));
            assert!(matches!(
                execute_case(surface, &case, &input),
                AdapterDisposition::Pass { .. }
            ));
        }
        for surface in [
            AdapterSurface::RustTextFindIter,
            AdapterSurface::RustTextCapturesIter,
            AdapterSurface::RustBytesFindIter,
            AdapterSurface::RustBytesCapturesIter,
        ] {
            assert_eq!(
                surface_applicability(surface, &case, &input),
                Err(NotApplicableReason::ProfileCannotRepresentMatchMode)
            );
        }

        case.utf8 = false;
        assert_eq!(
            surface_applicability(AdapterSurface::RustTextCompile, &case, &input),
            Err(NotApplicableReason::ProfileCannotRepresentUtf8Mode)
        );
        assert_eq!(
            surface_applicability(AdapterSurface::RustBytesCompile, &case, &input),
            Ok(())
        );
    }

    #[test]
    fn bytes_compile_is_independent_of_search_time_utf8_mode() {
        let case = fixture_case(true, true, None);
        let input = ExecutableCase {
            id: case.id.clone(),
            patterns: vec!["a".to_owned()],
            haystack: vec![0xFF],
            bounds: SearchBounds { start: 0, end: 1 },
            line_terminator: b'\n',
            expected: Vec::new(),
        };
        assert_eq!(
            surface_applicability(AdapterSurface::RustBytesCompile, &case, &input),
            Ok(())
        );
        assert!(matches!(
            execute_case(AdapterSurface::RustBytesCompile, &case, &input),
            AdapterDisposition::Pass { .. }
        ));
        assert_eq!(
            surface_applicability(AdapterSurface::RustBytesIsMatch, &case, &input),
            Err(NotApplicableReason::InvalidUtf8Haystack)
        );

        let rejected_case = fixture_case(false, true, None);
        let mut rejected_input = input;
        rejected_input.patterns = vec!["(".to_owned()];
        assert!(matches!(
            execute_case(
                AdapterSurface::RustBytesCompile,
                &rejected_case,
                &rejected_input,
            ),
            AdapterDisposition::Pass { .. }
        ));

        let bytes_only_case = fixture_case(true, false, None);
        assert_eq!(
            surface_applicability(
                AdapterSurface::RustTextCompile,
                &bytes_only_case,
                &rejected_input,
            ),
            Err(NotApplicableReason::ProfileCannotRepresentUtf8Mode)
        );
    }

    #[test]
    fn leftmost_all_single_surfaces_preserve_longest_and_capture_priority() {
        let span = |start, end| Some(ExpectedSpan { start, end });
        let cases = [
            ExecutableCase {
                id: "fixture/longest".to_owned(),
                patterns: vec!["(a)|(aa)".to_owned()],
                haystack: b"aa".to_vec(),
                bounds: SearchBounds { start: 0, end: 2 },
                line_terminator: b'\n',
                expected: vec![ExpectedCaptures {
                    pattern_id: 0,
                    groups: vec![span(0, 2), None, span(0, 2)],
                }],
            },
            ExecutableCase {
                id: "fixture/equal-end-priority".to_owned(),
                patterns: vec!["(a)|(a)".to_owned()],
                haystack: b"a".to_vec(),
                bounds: SearchBounds { start: 0, end: 1 },
                line_terminator: b'\n',
                expected: vec![ExpectedCaptures {
                    pattern_id: 0,
                    groups: vec![span(0, 1), span(0, 1), None],
                }],
            },
        ];

        for input in &cases {
            let mut text_case = fixture_case(true, true, None);
            text_case.match_kind = MatchKind::All;
            text_case.maximum_expected_capture_slots = 3;
            let mut bytes_case = text_case.clone();
            bytes_case.utf8 = false;
            for (surface, case) in [
                (AdapterSurface::RustTextFindIter, &text_case),
                (AdapterSurface::RustTextCapturesIter, &text_case),
                (AdapterSurface::RustBytesFindIter, &bytes_case),
                (AdapterSurface::RustBytesCapturesIter, &bytes_case),
            ] {
                assert_eq!(surface_applicability(surface, case, input), Ok(()));
                assert!(matches!(
                    execute_case(surface, case, input),
                    AdapterDisposition::Pass { .. }
                ));
            }
        }
    }

    #[test]
    #[allow(
        clippy::too_many_lines,
        reason = "the complete ranked upstream earliest corpus stays visible in one audit table"
    )]
    fn earliest_iterators_match_ranked_upstream_obligations() {
        struct EarliestCase {
            pattern: &'static str,
            haystack: &'static [u8],
            bounds: SearchBounds,
            anchored: bool,
            expected: Vec<ExpectedCaptures>,
        }

        let span = |start, end| Some(ExpectedSpan { start, end });
        let whole = |start, end| ExpectedCaptures {
            pattern_id: 0,
            groups: vec![span(start, end)],
        };
        let captured = |start, end, capture_start, capture_end| ExpectedCaptures {
            pattern_id: 0,
            groups: vec![span(start, end), span(capture_start, capture_end)],
        };
        let cases = [
            EarliestCase {
                pattern: "(abc)+",
                haystack: b"abcabcabc",
                bounds: SearchBounds { start: 0, end: 9 },
                anchored: true,
                expected: vec![
                    captured(0, 3, 0, 3),
                    captured(3, 6, 3, 6),
                    captured(6, 9, 6, 9),
                ],
            },
            EarliestCase {
                pattern: "a+",
                haystack: b"aaa",
                bounds: SearchBounds { start: 0, end: 3 },
                anchored: false,
                expected: vec![whole(0, 1), whole(1, 2), whole(2, 3)],
            },
            EarliestCase {
                pattern: "abc+",
                haystack: b"zzzabccc",
                bounds: SearchBounds { start: 0, end: 8 },
                anchored: false,
                expected: vec![whole(3, 6)],
            },
            EarliestCase {
                pattern: "a+?",
                haystack: b"aaa",
                bounds: SearchBounds { start: 0, end: 3 },
                anchored: false,
                expected: vec![whole(0, 1), whole(1, 2), whole(2, 3)],
            },
            EarliestCase {
                pattern: "^(abc|a)",
                haystack: b"abc",
                bounds: SearchBounds { start: 0, end: 3 },
                anchored: false,
                expected: vec![captured(0, 1, 0, 1)],
            },
            EarliestCase {
                pattern: "(abc|a)$",
                haystack: b"abc",
                bounds: SearchBounds { start: 0, end: 3 },
                anchored: false,
                expected: vec![captured(0, 3, 0, 3)],
            },
            EarliestCase {
                pattern: "abc|a",
                haystack: b"abc",
                bounds: SearchBounds { start: 0, end: 3 },
                anchored: false,
                expected: vec![whole(0, 1)],
            },
            EarliestCase {
                pattern: "aba|a",
                haystack: b"aba",
                bounds: SearchBounds { start: 0, end: 3 },
                anchored: false,
                expected: vec![whole(0, 1), whole(2, 3)],
            },
            EarliestCase {
                pattern: "c.*d\\z",
                haystack: b"ababcd",
                bounds: SearchBounds { start: 4, end: 6 },
                anchored: false,
                expected: vec![whole(4, 6)],
            },
            EarliestCase {
                pattern: "abc|b",
                haystack: b"abc",
                bounds: SearchBounds { start: 0, end: 3 },
                anchored: true,
                expected: vec![whole(0, 3)],
            },
        ];

        for (index, earliest) in cases.into_iter().enumerate() {
            let mut case = fixture_case(true, true, None);
            case.id = format!("fixture/earliest-{index}");
            case.upstream_name.clone_from(&case.id);
            case.search_kind = SearchKind::Earliest;
            case.anchored = earliest.anchored;
            case.unicode = true;
            case.bounded_search = earliest.bounds
                != (SearchBounds {
                    start: 0,
                    end: earliest.haystack.len(),
                });
            case.maximum_expected_capture_slots = earliest
                .expected
                .iter()
                .map(|matched| matched.groups.len())
                .max()
                .unwrap_or(0);
            let input = ExecutableCase {
                id: case.id.clone(),
                patterns: vec![earliest.pattern.to_owned()],
                haystack: earliest.haystack.to_vec(),
                bounds: earliest.bounds,
                line_terminator: b'\n',
                expected: earliest.expected,
            };
            for surface in [
                AdapterSurface::RustTextFindIter,
                AdapterSurface::RustTextCapturesIter,
                AdapterSurface::RustBytesFindIter,
                AdapterSurface::RustBytesCapturesIter,
            ] {
                assert_eq!(surface_applicability(surface, &case, &input), Ok(()));
                let disposition = execute_case(surface, &case, &input);
                assert!(
                    matches!(disposition, AdapterDisposition::Pass { .. }),
                    "earliest case {index} failed on {surface:?}: {disposition:?}"
                );
            }
        }
    }

    #[test]
    fn utf8_bytes_search_delegates_only_through_valid_text_equivalence() {
        let case = fixture_case(true, true, None);
        let input = fixture_input(vec![ExpectedCaptures {
            pattern_id: 0,
            groups: vec![Some(ExpectedSpan { start: 1, end: 2 })],
        }]);
        for surface in [
            AdapterSurface::RustBytesIsMatch,
            AdapterSurface::RustBytesFindIter,
            AdapterSurface::RustBytesCapturesIter,
        ] {
            assert_eq!(surface_applicability(surface, &case, &input), Ok(()));
            assert!(matches!(
                execute_case(surface, &case, &input),
                AdapterDisposition::Pass { .. }
            ));
        }
        let mut invalid = input.clone();
        invalid.haystack = vec![0xFF];
        invalid.bounds = SearchBounds { start: 0, end: 1 };
        for surface in [
            AdapterSurface::RustBytesIsMatch,
            AdapterSurface::RustBytesFindIter,
            AdapterSurface::RustBytesCapturesIter,
        ] {
            assert_eq!(
                surface_applicability(surface, &case, &invalid),
                Err(NotApplicableReason::InvalidUtf8Haystack)
            );
        }

        let rejected_case = fixture_case(false, true, None);
        for surface in [
            AdapterSurface::RustBytesIsMatch,
            AdapterSurface::RustBytesFindIter,
            AdapterSurface::RustBytesCapturesIter,
        ] {
            assert_eq!(
                surface_applicability(surface, &rejected_case, &input),
                Err(NotApplicableReason::CompileOnlyCase)
            );
        }
    }

    #[test]
    fn utf8_bytes_captures_preserve_multibyte_groups_and_empty_progress() {
        let mut case = fixture_case(true, true, None);
        case.unicode = true;
        case.maximum_expected_capture_slots = 3;
        let input = ExecutableCase {
            id: case.id.clone(),
            patterns: vec!["(é)(a)?".to_owned()],
            haystack: "é éa".as_bytes().to_vec(),
            bounds: SearchBounds { start: 0, end: 6 },
            line_terminator: b'\n',
            expected: vec![
                ExpectedCaptures {
                    pattern_id: 0,
                    groups: vec![
                        Some(ExpectedSpan { start: 0, end: 2 }),
                        Some(ExpectedSpan { start: 0, end: 2 }),
                        None,
                    ],
                },
                ExpectedCaptures {
                    pattern_id: 0,
                    groups: vec![
                        Some(ExpectedSpan { start: 3, end: 6 }),
                        Some(ExpectedSpan { start: 3, end: 5 }),
                        Some(ExpectedSpan { start: 5, end: 6 }),
                    ],
                },
            ],
        };
        for surface in [
            AdapterSurface::RustTextCapturesIter,
            AdapterSurface::RustBytesCapturesIter,
        ] {
            assert_eq!(surface_applicability(surface, &case, &input), Ok(()));
            assert!(matches!(
                execute_case(surface, &case, &input),
                AdapterDisposition::Pass { .. }
            ));
        }

        case.maximum_expected_capture_slots = 2;
        let empty = ExecutableCase {
            id: case.id.clone(),
            patterns: vec!["()".to_owned()],
            haystack: "éa".as_bytes().to_vec(),
            bounds: SearchBounds { start: 0, end: 3 },
            line_terminator: b'\n',
            expected: [0, 2, 3]
                .into_iter()
                .map(|offset| ExpectedCaptures {
                    pattern_id: 0,
                    groups: vec![
                        Some(ExpectedSpan {
                            start: offset,
                            end: offset,
                        }),
                        Some(ExpectedSpan {
                            start: offset,
                            end: offset,
                        }),
                    ],
                })
                .collect(),
        };
        for surface in [
            AdapterSurface::RustTextCapturesIter,
            AdapterSurface::RustBytesCapturesIter,
        ] {
            assert!(matches!(
                execute_case(surface, &case, &empty),
                AdapterDisposition::Pass { .. }
            ));
        }

        case.anchored = true;
        let anchored_empty = ExecutableCase {
            expected: vec![ExpectedCaptures {
                pattern_id: 0,
                groups: vec![
                    Some(ExpectedSpan { start: 0, end: 0 }),
                    Some(ExpectedSpan { start: 0, end: 0 }),
                ],
            }],
            ..empty
        };
        for surface in [
            AdapterSurface::RustTextCapturesIter,
            AdapterSurface::RustBytesCapturesIter,
        ] {
            assert!(matches!(
                execute_case(surface, &case, &anchored_empty),
                AdapterDisposition::Pass { .. }
            ));
        }
    }

    #[test]
    fn bounded_single_surfaces_use_context_preserving_windows() {
        let mut case = fixture_case(true, true, None);
        case.bounded_search = true;
        let input = ExecutableCase {
            id: case.id.clone(),
            patterns: vec![r"(?-u:\b)a".to_owned()],
            haystack: "éa a".as_bytes().to_vec(),
            bounds: SearchBounds { start: 2, end: 4 },
            line_terminator: b'\n',
            expected: vec![ExpectedCaptures {
                pattern_id: 0,
                groups: vec![Some(ExpectedSpan { start: 2, end: 3 })],
            }],
        };
        for surface in [
            AdapterSurface::RustTextCompile,
            AdapterSurface::RustTextIsMatch,
            AdapterSurface::RustTextFindIter,
        ] {
            assert_eq!(surface_applicability(surface, &case, &input), Ok(()));
            assert!(matches!(
                execute_case(surface, &case, &input),
                AdapterDisposition::Pass { .. }
            ));
        }
        for surface in [
            AdapterSurface::RustTextCapturesIter,
            AdapterSurface::RustBytesCapturesIter,
        ] {
            assert_eq!(surface_applicability(surface, &case, &input), Ok(()));
            assert!(matches!(
                execute_case(surface, &case, &input),
                AdapterDisposition::Pass { .. }
            ));
        }
        assert_eq!(
            surface_applicability(AdapterSurface::RustBytesCompile, &case, &input),
            Ok(())
        );
        assert!(matches!(
            execute_case(AdapterSurface::RustBytesCompile, &case, &input),
            AdapterDisposition::Pass { .. }
        ));
        for surface in [
            AdapterSurface::RustBytesIsMatch,
            AdapterSurface::RustBytesFindIter,
        ] {
            assert_eq!(surface_applicability(surface, &case, &input), Ok(()));
            assert!(matches!(
                execute_case(surface, &case, &input),
                AdapterDisposition::Pass { .. }
            ));
        }

        let mut bytes_case = fixture_case(true, false, None);
        bytes_case.bounded_search = true;
        let bytes_input = ExecutableCase {
            id: bytes_case.id.clone(),
            patterns: vec!["a".to_owned()],
            haystack: b"zaz".to_vec(),
            bounds: SearchBounds { start: 1, end: 2 },
            line_terminator: b'\n',
            expected: vec![ExpectedCaptures {
                pattern_id: 0,
                groups: vec![Some(ExpectedSpan { start: 1, end: 2 })],
            }],
        };
        for surface in [
            AdapterSurface::RustBytesCompile,
            AdapterSurface::RustBytesIsMatch,
            AdapterSurface::RustBytesFindIter,
        ] {
            assert_eq!(
                surface_applicability(surface, &bytes_case, &bytes_input),
                Ok(())
            );
            assert!(matches!(
                execute_case(surface, &bytes_case, &bytes_input),
                AdapterDisposition::Pass { .. }
            ));
        }
        assert_eq!(
            surface_applicability(
                AdapterSurface::RustBytesCapturesIter,
                &bytes_case,
                &bytes_input,
            ),
            Ok(())
        );
        assert!(matches!(
            execute_case(
                AdapterSurface::RustBytesCapturesIter,
                &bytes_case,
                &bytes_input,
            ),
            AdapterDisposition::Pass { .. }
        ));
    }

    #[test]
    fn split_utf8_capture_window_is_empty() {
        let case = fixture_case(true, true, None);
        let input = ExecutableCase {
            id: case.id.clone(),
            patterns: vec![String::new()],
            haystack: "é".as_bytes().to_vec(),
            bounds: SearchBounds { start: 1, end: 1 },
            line_terminator: b'\n',
            expected: Vec::new(),
        };
        for surface in [
            AdapterSurface::RustTextCapturesIter,
            AdapterSurface::RustBytesCapturesIter,
        ] {
            assert!(matches!(
                execute_case(surface, &case, &input),
                AdapterDisposition::Pass { .. }
            ));
        }
    }

    #[test]
    fn bounded_byte_capture_keeps_left_context() {
        let case = fixture_case(true, false, None);
        let input = ExecutableCase {
            id: case.id.clone(),
            patterns: vec![r"(?-u:\b)(a)".to_owned()],
            haystack: b"za a".to_vec(),
            bounds: SearchBounds { start: 1, end: 3 },
            line_terminator: b'\n',
            expected: Vec::new(),
        };
        assert!(matches!(
            execute_case(AdapterSurface::RustBytesCapturesIter, &case, &input),
            AdapterDisposition::Pass { .. }
        ));
    }

    #[test]
    fn ineligible_bounded_text_capture_keeps_bounds_precedence() {
        let case = fixture_case(true, false, None);
        let input = ExecutableCase {
            id: case.id.clone(),
            patterns: vec!["a".to_owned()],
            haystack: b"zaz".to_vec(),
            bounds: SearchBounds { start: 1, end: 2 },
            line_terminator: b'\n',
            expected: Vec::new(),
        };
        assert_eq!(
            surface_applicability(AdapterSurface::RustTextCapturesIter, &case, &input),
            Err(NotApplicableReason::ProfileCannotRepresentBounds)
        );
    }

    #[test]
    fn bounded_iteration_normalizes_utf8_endpoints_and_preserves_empty_progress() {
        let text = PortableTextBuilder::new("a|").build().unwrap();
        assert_eq!(
            collect_text_matches(
                &text,
                "xéay",
                SearchBounds { start: 2, end: 4 },
                None,
                false,
            )
            .unwrap(),
            vec![ExpectedSpan { start: 3, end: 4 }]
        );
        let empty = PortableTextBuilder::new("").build().unwrap();
        assert_eq!(
            collect_text_matches(&empty, "éa", SearchBounds { start: 0, end: 1 }, None, false,)
                .unwrap(),
            vec![ExpectedSpan { start: 0, end: 0 }]
        );
        assert_eq!(
            collect_text_matches(&empty, "éa", SearchBounds { start: 1, end: 1 }, None, false,)
                .unwrap(),
            Vec::<ExpectedSpan>::new()
        );

        let bytes = PortableBuilder::new("a|").build().unwrap();
        assert_eq!(
            collect_byte_matches(
                &bytes,
                b"abba",
                SearchBounds { start: 1, end: 3 },
                None,
                false,
            )
            .unwrap(),
            vec![
                ExpectedSpan { start: 1, end: 1 },
                ExpectedSpan { start: 2, end: 2 },
                ExpectedSpan { start: 3, end: 3 },
            ]
        );
    }

    #[test]
    fn upstream_compile_rejection_is_compared_not_hidden() {
        let case = fixture_case(false, false, None);
        let mut input = fixture_input(Vec::new());
        input.patterns = vec!["(".to_owned()];
        assert!(matches!(
            execute_case(AdapterSurface::RustBytesCompile, &case, &input),
            AdapterDisposition::Pass { .. }
        ));
        assert_eq!(
            surface_applicability(AdapterSurface::RustBytesIsMatch, &case, &input),
            Err(NotApplicableReason::CompileOnlyCase)
        );
    }

    #[test]
    fn wrong_expected_value_is_a_semantic_mismatch() {
        let case = fixture_case(true, false, None);
        let input = fixture_input(Vec::new());
        assert!(matches!(
            execute_bytes_is_match(&case, &input),
            AdapterDisposition::Mismatch { .. }
        ));
    }

    #[test]
    fn malformed_expected_capture_is_rejected() {
        let malformed = toml::Value::Array(vec![toml::Value::Array(Vec::new())]);
        assert!(decode_expected(&malformed, 1, 1).is_err());
    }

    fn fixture_case(compiles: bool, utf8: bool, match_limit: Option<usize>) -> CaseReceipt {
        CaseReceipt {
            id: "fixture/literal".to_owned(),
            upstream_name: "fixture/literal".to_owned(),
            source_file: "misc.toml".to_owned(),
            source_ordinal: 1,
            corpus_membership: CorpusMembership::RustRegexSuite,
            case_sha256: "0".repeat(64),
            pattern_count: 1,
            compiles,
            anchored: false,
            bounded_search: false,
            case_insensitive: false,
            unescape_haystack: false,
            unicode: false,
            utf8,
            custom_line_terminator: false,
            match_limit,
            match_kind: MatchKind::LeftmostFirst,
            search_kind: SearchKind::Leftmost,
            maximum_expected_capture_slots: 1,
            capabilities: vec![CapabilityId::PatternSingle],
        }
    }

    fn fixture_input(expected: Vec<ExpectedCaptures>) -> ExecutableCase {
        ExecutableCase {
            id: "fixture/literal".to_owned(),
            patterns: vec!["a".to_owned()],
            haystack: b"ba".to_vec(),
            bounds: SearchBounds { start: 0, end: 2 },
            line_terminator: b'\n',
            expected,
        }
    }
}
