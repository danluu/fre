//! Executable, no-clock adapter for the authenticated upstream corpus.

use std::{
    collections::{BTreeMap, BTreeSet},
    fs,
    io::Write,
    path::Path,
};

use bstr::ByteVec;
use fre::{BuildError, PortableBuilder, PortableRegex, RustProfile, SearchLimits};
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
/// Stable implementation identity for this first portable-facade adapter.
pub const ADAPTER_ID: &str = "fre-portable-rust-facade-v1";

const LIMITATIONS: [&str; 4] = [
    "the production FRE facade has no Rust text matcher",
    "the production FRE facade has no Rust text or bytes RegexSet matcher",
    "the production FRE facade has no capture iterator",
    "the production FRE facade has no complete match iterator; find-iter executes only empty-result or match-limit-one obligations",
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
#[derive(Clone, Debug, Eq, PartialEq)]
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
        AdapterSurface::RustTextCompile
        | AdapterSurface::RustTextIsMatch
        | AdapterSurface::RustTextFindIter
        | AdapterSurface::RustTextCapturesIter => {
            unsupported(CapabilityId::RustTextFacade, "facade.rust-text-missing")
        }
        AdapterSurface::RustTextSetCompile
        | AdapterSurface::RustTextSetIsMatch
        | AdapterSurface::RustTextSetWhich => unsupported(
            CapabilityId::RustTextSetFacade,
            "facade.rust-text-set-missing",
        ),
        AdapterSurface::RustBytesSetCompile
        | AdapterSurface::RustBytesSetIsMatch
        | AdapterSurface::RustBytesSetWhich => unsupported(
            CapabilityId::RustBytesSetFacade,
            "facade.rust-bytes-set-missing",
        ),
        AdapterSurface::RustBytesCapturesIter => unsupported(
            CapabilityId::CaptureIteration,
            "operation.captures-iter-missing",
        ),
        AdapterSurface::RustBytesCompile => execute_bytes_compile(case, input),
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
}

enum BuildAttempt {
    Built(Box<PortableRegex>),
    Rejected,
    Unsupported(AdapterDisposition),
    Fault(AdapterDisposition),
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
    match regex.is_match(&input.haystack, SearchLimits::unlimited()) {
        Ok((observed, _)) => compare(&expected, &SemanticValue::IsMatch(observed)),
        Err(_) => unsupported(
            CapabilityId::RustBytesFacade,
            "search.portable-execution-refused",
        ),
    }
}

fn execute_bytes_find(case: &CaseReceipt, input: &ExecutableCase) -> AdapterDisposition {
    if !input.expected.is_empty() && case.match_limit != Some(1) {
        return unsupported(CapabilityId::FindIteration, "operation.find-iter-missing");
    }
    let expected_spans = input
        .expected
        .iter()
        .map(|matched| {
            matched
                .groups
                .first()
                .and_then(|group| *group)
                .ok_or_else(|| InventoryError::new("expected match lacks participating group zero"))
        })
        .collect::<Result<Vec<_>, _>>();
    let Ok(expected_spans) = expected_spans else {
        return fault("adapter.expected-group-zero-missing");
    };
    let expected = SemanticValue::Matches(expected_spans);
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
    match regex.find(&input.haystack, SearchLimits::unlimited()) {
        Ok((matched, _)) => {
            let observed = matched
                .map(|matched| ExpectedSpan {
                    start: matched.start(),
                    end: matched.end(),
                })
                .into_iter()
                .collect();
            compare(&expected, &SemanticValue::Matches(observed))
        }
        Err(_) => unsupported(
            CapabilityId::RustBytesFacade,
            "search.portable-execution-refused",
        ),
    }
}

fn build_bytes(case: &CaseReceipt, input: &ExecutableCase) -> BuildAttempt {
    let Some(pattern) = input.patterns.first() else {
        return BuildAttempt::Fault(fault("adapter.single-pattern-missing"));
    };
    let mut profile = RustProfile::default();
    profile.options.case_insensitive = case.case_insensitive;
    profile.options.unicode = case.unicode;
    profile.options.line_terminator = input.line_terminator;
    match PortableBuilder::new(pattern.clone())
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
        | AdapterSurface::RustTextCapturesIter => single_applicability(case, input, true)?,
        AdapterSurface::RustBytesCompile
        | AdapterSurface::RustBytesIsMatch
        | AdapterSurface::RustBytesFindIter
        | AdapterSurface::RustBytesCapturesIter => single_applicability(case, input, false)?,
        AdapterSurface::RustTextSetCompile
        | AdapterSurface::RustTextSetIsMatch
        | AdapterSurface::RustTextSetWhich => set_applicability(case, input, true)?,
        AdapterSurface::RustBytesSetCompile
        | AdapterSurface::RustBytesSetIsMatch
        | AdapterSurface::RustBytesSetWhich => set_applicability(case, input, false)?,
    }
    if !is_compile_surface(surface) && !case.compiles {
        return Err(NotApplicableReason::CompileOnlyCase);
    }
    Ok(())
}

fn single_applicability(
    case: &CaseReceipt,
    input: &ExecutableCase,
    text: bool,
) -> Result<(), NotApplicableReason> {
    if input.patterns.len() != 1 {
        return Err(NotApplicableReason::PatternMultiplicity);
    }
    if case.search_kind != SearchKind::Leftmost {
        return Err(NotApplicableReason::ProfileCannotRepresentSearchMode);
    }
    if case.match_kind != MatchKind::LeftmostFirst {
        return Err(NotApplicableReason::ProfileCannotRepresentMatchMode);
    }
    if case.anchored && case.match_limit != Some(1) {
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

fn set_applicability(
    case: &CaseReceipt,
    input: &ExecutableCase,
    text: bool,
) -> Result<(), NotApplicableReason> {
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
    fn text_capture_and_unbounded_find_gaps_are_explicit() {
        let case = fixture_case(true, false, None);
        let input = fixture_input(vec![ExpectedCaptures {
            pattern_id: 0,
            groups: vec![Some(ExpectedSpan { start: 1, end: 2 })],
        }]);
        assert!(matches!(
            execute_bytes_find(&case, &input),
            AdapterDisposition::Unsupported {
                capability: CapabilityId::FindIteration,
                ..
            }
        ));
        assert_eq!(
            surface_applicability(AdapterSurface::RustTextCompile, &case, &input),
            Err(NotApplicableReason::ProfileCannotRepresentUtf8Mode)
        );

        let text_case = fixture_case(true, true, None);
        assert!(matches!(
            execute_case(AdapterSurface::RustTextCompile, &text_case, &input),
            AdapterDisposition::Unsupported {
                capability: CapabilityId::RustTextFacade,
                ..
            }
        ));
        assert!(matches!(
            execute_case(AdapterSurface::RustBytesCapturesIter, &case, &input),
            AdapterDisposition::Unsupported {
                capability: CapabilityId::CaptureIteration,
                ..
            }
        ));
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
