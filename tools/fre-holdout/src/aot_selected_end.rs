//! Native AOT `SelectedEnd` adapter for the authenticated holdout corpus.
//!
//! This is deliberately separate from the portable-FRE correctness and
//! performance reports in the parent module. A successful case compiles an
//! optimizing [`OutputContract::SelectedEnd`] object, publishes it directly in
//! memory through the strict-W^X loader, and calls only the published native
//! entry. A compile or publication decline remains an explicit receipt and is
//! never replaced by portable execution.

use std::{
    collections::BTreeMap,
    fs,
    hint::black_box,
    panic::{AssertUnwindSafe, catch_unwind},
    path::{Path, PathBuf},
    process::Command,
    time::Instant,
};
#[cfg(unix)]
use std::{ffi::OsString, os::unix::ffi::OsStringExt};

use fre_aot_regex::{
    Architecture, CallAbi, CompileError, CompileLimitsV1, CompileMode, CompileRequest,
    CompileResource, CompiledRegex, CpuFeature, DeterminizeLimits, FeatureSet, MatchResult,
    ObjectError, OperatingSystem, OptimizationPass, OutputContract, SearchWindow, Target, compile,
};
use fre_aot_regex_loader::{
    CallError, PublicationError, PublicationLimits, PublishedSelectedEnd,
    current_thread_sve_vector_length_bytes, host_target, publish_selected_end,
};
use fre_automata::CompileLimits as AutomataCompileLimits;
use fre_lower::LowerLimits;
use fre_syntax::RustProfile;
use regex::bytes::Regex;
use regex_automata::{Input, meta::Regex as MetaRegex, util::syntax};
use serde::{Deserialize, Serialize};

use super::{AuthenticatedSuite, CaseSpec, HoldoutError, TimingPolicy, authenticate_paths};

/// Deterministic native-AOT `SelectedEnd` correctness schema.
pub const AOT_SELECTED_END_CORRECTNESS_SCHEMA: &str = "fre.holdout.aot-selected-end.correctness.v1";
/// Non-normative paired native-AOT/Rust-regex timing schema.
pub const AOT_SELECTED_END_PERFORMANCE_SCHEMA: &str = "fre.holdout.aot-selected-end.performance.v1";
const AOT_SELECTED_END_WINDOW_MATRIX_SCHEMA: &str = "fre.holdout.aot-selected-end.window-matrix.v1";
const AOT_SELECTED_END_SCHEDULE_SCHEMA: &str = "fre.holdout.aot-selected-end.schedule.v1";
const AOT_SELECTED_END_LIMIT_POLICY_SCHEMA: &str = "fre.holdout.aot-selected-end.limits.v1";
const AOT_SELECTED_END_OBSERVATION_BUDGET_SCHEMA: &str =
    "fre.holdout.aot-selected-end.observation-budget.v1";
const MAX_TIMING_OBSERVATIONS: usize = 65_536;
const MIDSCAN_PREFIX: &[u8] = b"\xd3FRE-rg-midscan-prefix\x00";
const MIDSCAN_SUFFIX: &[u8] = b"\xffFRE-rg-midscan-bound\x00";
const CORRECTNESS_WINDOW_DERIVATION: &str = "for every authenticated expanded input: (1) its exact full SearchWindow; (2) a deterministic derived haystack MIDSCAN_PREFIX || input || MIDSCAN_SUFFIX with exact nonzero bounded window [prefix_bytes,prefix_bytes+input_bytes); matrix schema fre.holdout.aot-selected-end.window-matrix.v1";
const CORRECTNESS_ORACLE_IDENTITY: &str = "mandatory expectation is same-artifact fre-aot-regex CompiledRegex::search(haystack, SearchWindow) SelectedEnd; independent full-window baseline is regex::bytes 1.12.4 unicode=false find().end(); every independent bounded baseline is regex-automata 0.4.15 meta Input::span over the full haystack, which preserves absolute \\A and \\z context";
const CORRECTNESS_CANDIDATE_IDENTITY: &str = "fre-aot-regex optimizing OutputContract::SelectedEnd published by fre-aot-regex-loader in memory under strict W^X; direct native entry only; no portable executor or external linker";
const CORRECTNESS_APPLICABILITY: &str = "a search window is applicable exactly when its case pattern compiles and publishes; every full and midscan window behind a decline or fault remains a receipt rather than disappearing or falling back";
const PERFORMANCE_CANDIDATE_IDENTITY: &str = "fre-aot-regex optimizing SelectedEnd plus fre-aot-regex-loader direct in-memory native publication; no portable FRE fallback and no external linker";
const PERFORMANCE_ORACLE_IDENTITY: &str = "the exact validated same-artifact portable SelectedEnd expectation from correctness for each authenticated full/midscan SearchWindow";
const COLD_MEASUREMENT_SCOPE: &str = "each point constructs a fresh matcher for the identical authenticated window; FRE records compile, in-memory strict-W^X publish, first native scan, and the enclosing compile+publish+first-scan transaction separately; the Rust engine records regex-automata 0.4.15 meta compile, first full-haystack Input::span scan, and its enclosing transaction; classification and semantic comparison occur after each clock sample";
const HOT_MEASUREMENT_SCOPE: &str = "one matcher per case is constructed outside warmup and measured search samples; FRE search_ns is one bounded call through the reused published SelectedEnd entry and the Rust engine search_ns is one full-haystack regex-automata Input::span call; setup durations and all declines/faults remain separate receipts";
const PAIRING_SCHEDULE_DESCRIPTION: &str = "every cold/hot warmup/measurement sweep is a recorded authenticated seeded permutation of all full/midscan windows; adjacent sweeps use a permutation and its reverse, engine-first order alternates per input and repetition, and both engines remain in one paired point";

/// Paths needed for one authenticated native-AOT run.
#[derive(Clone, Debug)]
pub struct AotSelectedEndRunConfig {
    pub suite: PathBuf,
    pub schema: PathBuf,
    pub digests: PathBuf,
    pub correctness_output: PathBuf,
    pub performance_output: Option<PathBuf>,
}

/// Whether one case reached a callable in-memory native entry.
#[derive(Clone, Copy, Debug, Deserialize, Serialize, Eq, Ord, PartialEq, PartialOrd)]
#[serde(rename_all = "kebab-case")]
pub enum AotSelectedEndDisposition {
    Ready,
    Declined,
    Fault,
}

/// Result of comparing one expanded input with `regex::bytes::find().end()`.
#[derive(Clone, Copy, Debug, Deserialize, Serialize, Eq, Ord, PartialEq, PartialOrd)]
#[serde(rename_all = "kebab-case")]
pub enum AotSelectedEndComparisonStatus {
    Pass,
    Declined,
    Fail,
    Fault,
}

/// Authenticated search-window shape used by correctness and timing.
#[derive(Clone, Copy, Debug, Deserialize, Serialize, Eq, Ord, PartialEq, PartialOrd)]
#[serde(rename_all = "kebab-case")]
pub enum AotSelectedEndWindowKind {
    Full,
    MidscanNonzeroBounded,
}

/// Exact native compiler target retained across correctness and performance.
#[derive(Clone, Debug, Deserialize, Serialize, Eq, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct AotSelectedEndTargetReceipt {
    pub architecture: String,
    pub operating_system: String,
    pub abi: String,
    pub feature_bits: u64,
    pub debug_identity: String,
    pub sve_vector_length_bytes: Option<u16>,
    pub sve_vector_length_source: String,
}

/// Host target resolution is retained even if no case can be compiled.
#[derive(Clone, Debug, Deserialize, Serialize, Eq, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct AotSelectedEndHostReceipt {
    pub disposition: AotSelectedEndDisposition,
    pub target: Option<AotSelectedEndTargetReceipt>,
    pub reason_code: Option<String>,
    pub reason: Option<String>,
}

/// Source, build, executable, and runtime host identity captured outside clocks.
#[derive(Clone, Debug, Deserialize, Serialize, Eq, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct AotSelectedEndProvenanceReceipt {
    pub source_commit: String,
    pub source_tree_at_build: String,
    pub source_tree_at_run: String,
    pub source_status_sha256_at_build: String,
    pub source_status_sha256_at_run: String,
    pub source_diff_sha256_at_build: String,
    pub source_diff_sha256_at_run: String,
    pub source_untracked_sha256_at_build: String,
    pub source_untracked_sha256_at_run: String,
    pub build_profile: String,
    pub build_target: String,
    pub build_host: String,
    pub rustc_version: String,
    pub executable_sha256: String,
    pub runtime_kernel: String,
    pub runtime_hostname: String,
}

/// Frozen effective compiler ceilings used by correctness and timing builds.
#[derive(Clone, Debug, Deserialize, Serialize, Eq, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct AotSelectedEndCompileLimitsReceipt {
    pub lower_max_work: u64,
    pub lower_max_stack_items: usize,
    pub automata_max_states: usize,
    pub automata_max_edges: usize,
    pub automata_max_storage_bytes: usize,
    pub automata_max_validation_work: usize,
    pub determinize_max_states: usize,
    pub determinize_max_transitions: usize,
    pub determinize_max_work: u64,
    pub max_program_bytes: usize,
    pub max_object_bytes: usize,
}

/// Frozen strict-W^X in-memory publication ceilings.
#[derive(Clone, Debug, Deserialize, Serialize, Eq, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct AotSelectedEndPublicationLimitsReceipt {
    pub max_sections: usize,
    pub max_relocations: usize,
    pub max_code_bytes: usize,
    pub max_read_only_data_bytes: usize,
    pub max_scratch_bytes: usize,
    pub max_mapped_bytes: usize,
}

/// Exact resource policy shared by every AOT compilation/publication stage.
#[derive(Clone, Debug, Deserialize, Serialize, Eq, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct AotSelectedEndLimitPolicyReceipt {
    pub schema: String,
    pub compile: AotSelectedEndCompileLimitsReceipt,
    pub publication: AotSelectedEndPublicationLimitsReceipt,
}

/// Checked cardinality of the complete timing campaign before allocation.
#[derive(Clone, Debug, Deserialize, Serialize, Eq, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct AotSelectedEndObservationBudgetReceipt {
    pub schema: String,
    pub maximum_timing_observations: usize,
    pub authenticated_search_windows: usize,
    pub authenticated_case_patterns: usize,
    pub warmup_sweeps_per_mode: usize,
    pub measured_sweeps_per_mode: usize,
    pub planned_paired_points: usize,
    pub planned_paired_engine_observations: usize,
    pub planned_hot_setup_observations: usize,
    pub planned_total_timing_observations: usize,
}

/// Selected target-neutral and native machine geometry.
#[derive(Clone, Debug, Deserialize, Serialize, Eq, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct AotSelectedEndMachineEvidence {
    pub state_source: String,
    pub forward_states: Option<usize>,
    pub reverse_states: Option<usize>,
    pub reverse_start_recovery: bool,
}

/// Stable evidence copied from a successful compiler receipt before publish.
#[derive(Clone, Debug, Deserialize, Serialize, Eq, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct AotSelectedEndCompilerEvidence {
    pub compiler_version: u32,
    pub optimizer_version: u32,
    pub mode: String,
    pub output_contract: String,
    pub entry_abi: String,
    pub target: String,
    pub target_feature_bits: u64,
    pub line_terminator: u8,
    pub object_sha256: String,
    pub engine: String,
    pub engine_selection_reason: String,
    pub determinization_decline: Option<String>,
    pub context_determinization_decline: Option<String>,
    pub optimization_passes: Vec<String>,
    pub machine: AotSelectedEndMachineEvidence,
    pub thompson_states: usize,
    pub thompson_edges: usize,
    pub program_bytes: usize,
    pub code_bytes: usize,
    pub data_bytes: usize,
    pub object_bytes: usize,
}

/// Stable accounting copied from the published executable mapping.
#[derive(Clone, Debug, Deserialize, Serialize, Eq, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct AotSelectedEndPublicationEvidence {
    pub identity_sha256: String,
    pub target: String,
    pub target_feature_bits: u64,
    pub page_bytes: usize,
    pub section_count: usize,
    pub relocation_count: usize,
    pub code_bytes: usize,
    pub read_only_data_bytes: usize,
    pub scratch_bytes: usize,
    pub padding_bytes: usize,
    pub guard_bytes: usize,
    pub payload_mapped_bytes: usize,
    pub total_mapped_bytes: usize,
}

/// One compile-and-publication result per frozen case pattern.
#[derive(Clone, Debug, Deserialize, Serialize, Eq, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct AotSelectedEndCaseReceipt {
    pub case_id: String,
    pub family: String,
    pub labels: Vec<String>,
    pub pattern_sha256: String,
    pub input_count: usize,
    pub search_window_count: usize,
    pub disposition: AotSelectedEndDisposition,
    pub terminal_stage: String,
    pub reason_code: Option<String>,
    pub reason: Option<String>,
    pub compiler: Option<AotSelectedEndCompilerEvidence>,
    pub publication: Option<AotSelectedEndPublicationEvidence>,
}

/// One comparison for every expanded input, including inputs behind a decline.
#[derive(Clone, Debug, Deserialize, Serialize, Eq, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct AotSelectedEndComparisonReceipt {
    pub case_id: String,
    pub family: String,
    pub labels: Vec<String>,
    pub input_ordinal: usize,
    pub declared_intent: String,
    pub window_kind: AotSelectedEndWindowKind,
    pub source_haystack_sha256: String,
    pub haystack_sha256: String,
    pub haystack_bytes: usize,
    pub window_start: usize,
    pub window_end: usize,
    pub independent_oracle_kind: String,
    pub independent_end: Option<usize>,
    pub portable_call_attempted: bool,
    pub expected_end: Option<usize>,
    pub actual_end: Option<usize>,
    pub native_call_attempted: bool,
    pub status: AotSelectedEndComparisonStatus,
    pub reason_code: Option<String>,
    pub reason: Option<String>,
}

/// Exact deterministic native-AOT coverage counters.
#[derive(Clone, Debug, Default, Deserialize, Serialize, Eq, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct AotSelectedEndCoverage {
    pub case_patterns: usize,
    pub expanded_inputs: usize,
    pub search_windows: usize,
    pub applicable_search_windows: usize,
    pub by_case_disposition: BTreeMap<AotSelectedEndDisposition, usize>,
    pub by_input_status: BTreeMap<AotSelectedEndComparisonStatus, usize>,
    pub by_window_kind_status:
        BTreeMap<AotSelectedEndWindowKind, BTreeMap<AotSelectedEndComparisonStatus, usize>>,
    pub by_family_input_status: BTreeMap<String, BTreeMap<AotSelectedEndComparisonStatus, usize>>,
}

/// Clock-free native-AOT `SelectedEnd` correctness report.
#[derive(Clone, Debug, Deserialize, Serialize, Eq, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct AotSelectedEndCorrectnessReport {
    pub schema: String,
    pub suite_id: String,
    pub suite_sha256: String,
    pub json_schema_sha256: String,
    pub expanded_inputs_sha256: String,
    pub window_matrix_sha256: String,
    pub window_derivation: String,
    pub oracle_identity: String,
    pub candidate_identity: String,
    pub applicability: String,
    pub target_arch: String,
    pub target_os: String,
    pub target_pointer_width: u32,
    pub host: AotSelectedEndHostReceipt,
    pub provenance: AotSelectedEndProvenanceReceipt,
    pub limit_policy: AotSelectedEndLimitPolicyReceipt,
    pub provenance_sha256: String,
    pub receipts_sha256: String,
    pub coverage: AotSelectedEndCoverage,
    pub cases: Vec<AotSelectedEndCaseReceipt>,
    pub comparisons: Vec<AotSelectedEndComparisonReceipt>,
}

#[derive(Debug)]
struct LiveCaseBuild {
    receipt: AotSelectedEndCaseReceipt,
    portable: Option<CompiledRegex>,
    published: Option<PublishedSelectedEnd>,
}

struct IndependentOracle {
    full: Regex,
    bounded: MetaRegex,
}

#[derive(Debug)]
struct TargetReceiptFailure {
    code: String,
    reason: String,
    receipt: AotSelectedEndTargetReceipt,
}

#[derive(Clone, Debug, Serialize)]
struct AotSelectedEndSearchInput {
    source_index: usize,
    case_id: String,
    family: String,
    labels: Vec<String>,
    pattern: String,
    input_ordinal: usize,
    declared_intent: String,
    window_kind: AotSelectedEndWindowKind,
    source_haystack_sha256: String,
    haystack: Vec<u8>,
    window_start: usize,
    window_end: usize,
}

/// Authenticate, run the clock-free native correctness pass, then optionally
/// write the separate non-normative timing report.
pub fn run_aot_selected_end(
    config: &AotSelectedEndRunConfig,
) -> Result<AotSelectedEndCorrectnessReport, HoldoutError> {
    let authenticated = authenticate_paths(&config.suite, &config.schema, &config.digests)?;
    let correctness = run_aot_selected_end_correctness(&authenticated)?;
    super::write_json(&config.correctness_output, &correctness)?;
    if let Some(path) = &config.performance_output {
        let performance = run_aot_selected_end_performance(&authenticated, &correctness)?;
        super::write_json(path, &performance)?;
    }
    Ok(correctness)
}

/// Execute direct-native full and bounded nonzero-start comparisons for every
/// authenticated expanded input. Cases that decline or fault still produce
/// every comparison receipt, so coverage cannot silently shrink.
pub fn run_aot_selected_end_correctness(
    authenticated: &AuthenticatedSuite,
) -> Result<AotSelectedEndCorrectnessReport, HoldoutError> {
    // Reject a stale executable before host resolution, compilation,
    // publication, or any candidate/oracle correctness call.
    let provenance = collect_provenance()?;
    let (host, target) = resolve_host_target();
    let search_inputs = aot_search_inputs(authenticated)?;
    let window_matrix_sha256 = aot_window_matrix_sha256(authenticated, &search_inputs)?;
    let mut cases = Vec::new();
    let mut comparisons = Vec::new();
    for case in &authenticated.manifest.cases {
        let oracle = independent_oracle(&case.pattern).map_err(|error| {
            HoldoutError::new(format!(
                "case {} AOT SelectedEnd independent oracle construction: {error}",
                case.id
            ))
        })?;
        let expanded_input_count = authenticated
            .inputs
            .iter()
            .filter(|input| input.case_id == case.id)
            .count();
        let inputs = search_inputs
            .iter()
            .filter(|input| input.case_id == case.id)
            .collect::<Vec<_>>();
        let built = match target {
            Some(target) => build_case(case, expanded_input_count, inputs.len(), target),
            None => unavailable_case(case, expanded_input_count, inputs.len(), &host),
        };
        for input in inputs {
            let (independent_oracle_kind, independent_end) = independent_end(&oracle, input);
            comparisons.push(compare_input(
                input,
                independent_oracle_kind,
                independent_end,
                &built.receipt,
                built.portable.as_ref(),
                built.published.as_ref(),
            ));
        }
        cases.push(built.receipt);
    }

    if cases.len() != authenticated.manifest.cases.len() || comparisons.len() != search_inputs.len()
    {
        return Err(HoldoutError::new(format!(
            "AOT SelectedEnd generated {} case and {} window receipts, expected {} and {}",
            cases.len(),
            comparisons.len(),
            authenticated.manifest.cases.len(),
            search_inputs.len()
        )));
    }
    let coverage = aot_coverage(&cases, &comparisons);
    let provenance_bytes = serde_json::to_vec(&(&host, &provenance))
        .map_err(|error| HoldoutError::new(format!("serialize AOT provenance digest: {error}")))?;
    let limit_policy = selected_end_limit_policy();
    let receipt_bytes =
        serde_json::to_vec(&(&limit_policy, &cases, &comparisons)).map_err(|error| {
            HoldoutError::new(format!("serialize AOT SelectedEnd receipt digest: {error}"))
        })?;
    let report = AotSelectedEndCorrectnessReport {
        schema: AOT_SELECTED_END_CORRECTNESS_SCHEMA.to_string(),
        suite_id: authenticated.manifest.suite_id.clone(),
        suite_sha256: authenticated.suite_sha256.clone(),
        json_schema_sha256: authenticated.json_schema_sha256.clone(),
        expanded_inputs_sha256: authenticated.expanded_inputs_sha256.clone(),
        window_matrix_sha256,
        window_derivation: CORRECTNESS_WINDOW_DERIVATION.to_string(),
        oracle_identity: CORRECTNESS_ORACLE_IDENTITY.to_string(),
        candidate_identity: CORRECTNESS_CANDIDATE_IDENTITY.to_string(),
        applicability: CORRECTNESS_APPLICABILITY.to_string(),
        target_arch: std::env::consts::ARCH.to_string(),
        target_os: std::env::consts::OS.to_string(),
        target_pointer_width: usize::BITS,
        host,
        provenance,
        limit_policy,
        provenance_sha256: super::sha256(&provenance_bytes),
        receipts_sha256: super::sha256(&receipt_bytes),
        coverage,
        cases,
        comparisons,
    };
    validate_aot_selected_end_correctness(authenticated, &report)?;
    Ok(report)
}

/// Reject semantic mismatches and implementation faults while retaining
/// resource/capability declines as explicit coverage gaps.
pub fn enforce_aot_selected_end_strict_gate(
    report: &AotSelectedEndCorrectnessReport,
) -> Result<(), HoldoutError> {
    let failures = report
        .coverage
        .by_input_status
        .get(&AotSelectedEndComparisonStatus::Fail)
        .copied()
        .unwrap_or(0);
    let input_faults = report
        .coverage
        .by_input_status
        .get(&AotSelectedEndComparisonStatus::Fault)
        .copied()
        .unwrap_or(0);
    let case_faults = report
        .coverage
        .by_case_disposition
        .get(&AotSelectedEndDisposition::Fault)
        .copied()
        .unwrap_or(0);
    if failures == 0 && input_faults == 0 && case_faults == 0 {
        Ok(())
    } else {
        Err(HoldoutError::new(format!(
            "strict AOT SelectedEnd gate rejected {failures} semantic failures, {input_faults} input faults, and {case_faults} case-build faults; inspect the already-written receipts"
        )))
    }
}

/// Require enough native coverage to make timing evidence meaningful.
pub fn enforce_aot_selected_end_readiness_floor(
    report: &AotSelectedEndCorrectnessReport,
) -> Result<(), HoldoutError> {
    let mut ready_case_windows = report
        .cases
        .iter()
        .filter(|case| case.disposition == AotSelectedEndDisposition::Ready)
        .map(|case| (case.case_id.as_str(), (false, false)))
        .collect::<BTreeMap<_, _>>();
    for comparison in &report.comparisons {
        if comparison.status != AotSelectedEndComparisonStatus::Pass {
            continue;
        }
        let Some((full, midscan)) = ready_case_windows.get_mut(comparison.case_id.as_str()) else {
            continue;
        };
        match comparison.window_kind {
            AotSelectedEndWindowKind::Full => *full = true,
            AotSelectedEndWindowKind::MidscanNonzeroBounded => *midscan = true,
        }
    }
    let ready_cases = ready_case_windows.len();
    let missing_case_windows = ready_case_windows
        .iter()
        .filter(|(_, (full, midscan))| !(*full && *midscan))
        .map(|(case_id, (full, midscan))| format!("{case_id}(full={full},midscan={midscan})"))
        .collect::<Vec<_>>();
    let minimum_ready_cases = report.cases.len().div_ceil(2).max(1);
    if report.host.disposition == AotSelectedEndDisposition::Ready
        && ready_cases >= minimum_ready_cases
        && missing_case_windows.is_empty()
    {
        Ok(())
    } else {
        Err(HoldoutError::new(format!(
            "AOT SelectedEnd timing readiness floor requires a ready host, at least half of case patterns ready ({minimum_ready_cases}), and at least one passing full and bounded midscan window for every ready case; observed host={:?}, ready_cases={ready_cases}, missing_case_windows={missing_case_windows:?}",
            report.host.disposition,
        )))
    }
}

fn readiness_floor_description(report: &AotSelectedEndCorrectnessReport) -> String {
    format!(
        "validated correctness strict gate; ready host; at least half of case patterns ready ({} of {}); at least one passing full and bounded nonzero-start midscan window per ready case",
        report.coverage.case_patterns.div_ceil(2).max(1),
        report.coverage.case_patterns,
    )
}

fn resolve_host_target() -> (AotSelectedEndHostReceipt, Option<Target>) {
    match catch_unwind(AssertUnwindSafe(host_target)) {
        Err(_) => (
            AotSelectedEndHostReceipt {
                disposition: AotSelectedEndDisposition::Fault,
                target: None,
                reason_code: Some("host-target.panic".to_string()),
                reason: Some("host target detection panicked".to_string()),
            },
            None,
        ),
        Ok(Err(error)) => {
            let disposition = host_target_error_disposition(&error);
            (
                AotSelectedEndHostReceipt {
                    disposition,
                    target: None,
                    reason_code: Some(host_target_error_code(&error)),
                    reason: Some(error.to_string()),
                },
                None,
            )
        }
        Ok(Ok(target)) => match target_receipt(target) {
            Ok(target_receipt) => (
                AotSelectedEndHostReceipt {
                    disposition: AotSelectedEndDisposition::Ready,
                    target: Some(target_receipt),
                    reason_code: None,
                    reason: None,
                },
                Some(target),
            ),
            Err(failure) => {
                let TargetReceiptFailure {
                    code,
                    reason,
                    receipt,
                } = *failure;
                (
                    AotSelectedEndHostReceipt {
                        disposition: AotSelectedEndDisposition::Fault,
                        target: Some(receipt),
                        reason_code: Some(code),
                        reason: Some(reason),
                    },
                    None,
                )
            }
        },
    }
}

fn target_receipt(
    target: Target,
) -> Result<AotSelectedEndTargetReceipt, Box<TargetReceiptFailure>> {
    let requires_sve = target
        .features
        .contains(FeatureSet::of(CpuFeature::Aarch64Sve));
    let base =
        |sve_vector_length_bytes, sve_vector_length_source: &str| AotSelectedEndTargetReceipt {
            architecture: format!("{:?}", target.architecture),
            operating_system: format!("{:?}", target.operating_system),
            abi: format!("{:?}", target.abi),
            feature_bits: target.features.bits(),
            debug_identity: format!("{target:?}"),
            sve_vector_length_bytes,
            sve_vector_length_source: sve_vector_length_source.to_string(),
        };
    if !requires_sve {
        return Ok(base(None, "not-applicable-target-has-no-sve"));
    }
    match catch_unwind(AssertUnwindSafe(current_thread_sve_vector_length_bytes)) {
        Err(_) => {
            let receipt = base(None, "linux-prctl-pr-sve-get-vl-panicked");
            Err(Box::new(TargetReceiptFailure {
                code: "host-target.fault.sve-vector-length-panic".to_string(),
                reason: "current-thread SVE vector-length query panicked".to_string(),
                receipt,
            }))
        }
        Ok(Err(errno)) => {
            let receipt = base(None, "linux-prctl-pr-sve-get-vl-failed");
            Err(Box::new(TargetReceiptFailure {
                code: "host-target.fault.sve-vector-length-query".to_string(),
                reason: format!("PR_SVE_GET_VL failed with errno {errno}"),
                receipt,
            }))
        }
        Ok(Ok(None)) => {
            let receipt = base(None, "sve-target-without-platform-observation");
            Err(Box::new(TargetReceiptFailure {
                code: "host-target.fault.sve-vector-length-unavailable".to_string(),
                reason: "target requires SVE but current-thread vector length was not observable"
                    .to_string(),
                receipt,
            }))
        }
        Ok(Ok(Some(bytes))) => Ok(base(Some(bytes), "linux-prctl-pr-sve-get-vl")),
    }
}

fn unavailable_case(
    case: &CaseSpec,
    input_count: usize,
    search_window_count: usize,
    host: &AotSelectedEndHostReceipt,
) -> LiveCaseBuild {
    LiveCaseBuild {
        receipt: AotSelectedEndCaseReceipt {
            case_id: case.id.clone(),
            family: case.family.clone(),
            labels: case.labels.clone(),
            pattern_sha256: super::sha256(case.pattern.as_bytes()),
            input_count,
            search_window_count,
            disposition: host.disposition,
            terminal_stage: "host-target".to_string(),
            reason_code: host.reason_code.clone(),
            reason: host.reason.clone(),
            compiler: None,
            publication: None,
        },
        portable: None,
        published: None,
    }
}

fn build_case(
    case: &CaseSpec,
    input_count: usize,
    search_window_count: usize,
    target: Target,
) -> LiveCaseBuild {
    let artifact = match catch_unwind(AssertUnwindSafe(|| {
        compile(selected_end_request(&case.pattern, target))
    })) {
        Err(_) => {
            return failed_case(
                case,
                input_count,
                search_window_count,
                AotSelectedEndDisposition::Fault,
                "compile",
                "compile.panic",
                "AOT SelectedEnd compiler panicked".to_string(),
                None,
            );
        }
        Ok(Err(error)) => {
            return failed_case(
                case,
                input_count,
                search_window_count,
                compile_error_disposition(&error),
                "compile",
                &compile_error_code(&error),
                error.to_string(),
                None,
            );
        }
        Ok(Ok(compiled)) => compiled,
    };
    let compiler_receipt = compiler_evidence(&artifact);
    let portable = artifact.clone();
    let published = match catch_unwind(AssertUnwindSafe(|| {
        publish_selected_end(artifact, selected_end_publication_limits())
    })) {
        Err(_) => {
            return failed_case(
                case,
                input_count,
                search_window_count,
                AotSelectedEndDisposition::Fault,
                "publish",
                "publish.panic",
                "in-memory AOT SelectedEnd publication panicked".to_string(),
                Some(compiler_receipt),
            );
        }
        Ok(Err(error)) => {
            return failed_case(
                case,
                input_count,
                search_window_count,
                publication_error_disposition(&error),
                "publish",
                &publication_error_code(&error, "publish"),
                error.to_string(),
                Some(compiler_receipt),
            );
        }
        Ok(Ok(published)) => published,
    };
    let publication = publication_evidence(&published);
    LiveCaseBuild {
        receipt: AotSelectedEndCaseReceipt {
            case_id: case.id.clone(),
            family: case.family.clone(),
            labels: case.labels.clone(),
            pattern_sha256: super::sha256(case.pattern.as_bytes()),
            input_count,
            search_window_count,
            disposition: AotSelectedEndDisposition::Ready,
            terminal_stage: "ready".to_string(),
            reason_code: None,
            reason: None,
            compiler: Some(compiler_receipt),
            publication: Some(publication),
        },
        portable: Some(portable),
        published: Some(published),
    }
}

#[allow(
    clippy::too_many_arguments,
    reason = "the terminal case receipt keeps authenticated identity, stage, classification, reason, and optional compiler evidence explicit"
)]
fn failed_case(
    case: &CaseSpec,
    input_count: usize,
    search_window_count: usize,
    disposition: AotSelectedEndDisposition,
    terminal_stage: &str,
    reason_code: &str,
    reason: String,
    compiler: Option<AotSelectedEndCompilerEvidence>,
) -> LiveCaseBuild {
    LiveCaseBuild {
        receipt: AotSelectedEndCaseReceipt {
            case_id: case.id.clone(),
            family: case.family.clone(),
            labels: case.labels.clone(),
            pattern_sha256: super::sha256(case.pattern.as_bytes()),
            input_count,
            search_window_count,
            disposition,
            terminal_stage: terminal_stage.to_string(),
            reason_code: Some(reason_code.to_string()),
            reason: Some(reason),
            compiler,
            publication: None,
        },
        portable: None,
        published: None,
    }
}

fn selected_end_request(pattern: &str, target: Target) -> CompileRequest {
    let mut profile = RustProfile::regex_1_12_4();
    profile.options.unicode = false;
    CompileRequest::new(pattern, target)
        .profile(profile)
        .limits(selected_end_compile_limits())
        .mode(CompileMode::Optimizing)
        .output(OutputContract::SelectedEnd)
}

fn selected_end_compile_limits() -> CompileLimitsV1 {
    CompileLimitsV1 {
        lower: LowerLimits {
            max_work: 8_000_000,
            max_stack_items: 1_000_000,
            automata: AutomataCompileLimits {
                max_states: 262_144,
                max_edges: 1_048_576,
                max_storage_bytes: 128 * 1_024 * 1_024,
                max_validation_work: 4_000_000,
            },
        },
        determinize: DeterminizeLimits {
            max_states: 262_144,
            max_transitions: 16_777_216,
            max_work: 500_000_000,
        },
        // regex::bytes::RegexBuilder 1.12.4's frozen size_limit.
        max_program_bytes: 10 * (1 << 20),
        max_object_bytes: 512 * 1_024 * 1_024,
    }
}

fn selected_end_publication_limits() -> PublicationLimits {
    PublicationLimits {
        max_sections: 16,
        max_relocations: 8_388_608,
        max_code_bytes: 536_870_912,
        max_read_only_data_bytes: 536_870_912,
        max_scratch_bytes: 536_870_912,
        max_mapped_bytes: 1_073_741_824,
    }
}

fn selected_end_limit_policy() -> AotSelectedEndLimitPolicyReceipt {
    let compile = selected_end_compile_limits();
    let publication = selected_end_publication_limits();
    AotSelectedEndLimitPolicyReceipt {
        schema: AOT_SELECTED_END_LIMIT_POLICY_SCHEMA.to_string(),
        compile: AotSelectedEndCompileLimitsReceipt {
            lower_max_work: compile.lower.max_work,
            lower_max_stack_items: compile.lower.max_stack_items,
            automata_max_states: compile.lower.automata.max_states,
            automata_max_edges: compile.lower.automata.max_edges,
            automata_max_storage_bytes: compile.lower.automata.max_storage_bytes,
            automata_max_validation_work: compile.lower.automata.max_validation_work,
            determinize_max_states: compile.determinize.max_states,
            determinize_max_transitions: compile.determinize.max_transitions,
            determinize_max_work: compile.determinize.max_work,
            max_program_bytes: compile.max_program_bytes,
            max_object_bytes: compile.max_object_bytes,
        },
        publication: AotSelectedEndPublicationLimitsReceipt {
            max_sections: publication.max_sections,
            max_relocations: publication.max_relocations,
            max_code_bytes: publication.max_code_bytes,
            max_read_only_data_bytes: publication.max_read_only_data_bytes,
            max_scratch_bytes: publication.max_scratch_bytes,
            max_mapped_bytes: publication.max_mapped_bytes,
        },
    }
}

fn compiler_evidence(compiled: &CompiledRegex) -> AotSelectedEndCompilerEvidence {
    let receipt = compiled.receipt();
    let (state_source, forward_states, reverse_states) =
        if let Some(slow) = &receipt.slow_context_aot {
            (
                "slow-context-aot",
                Some(slow.dfa.forward_states),
                Some(slow.dfa.reverse_states),
            )
        } else if let Some(k0) = &receipt.compiler_k0_aot {
            (
                "compiler-k0-aot",
                Some(k0.finalization.output.forward_states),
                Some(k0.finalization.output.reverse_states),
            )
        } else if let Some(slow) = &receipt.slow_aot {
            (
                "slow-aot",
                Some(slow.dfa.forward_states),
                Some(slow.dfa.reverse_states),
            )
        } else if let Some(finite) = receipt.ordered_finite_language_aot {
            ("ordered-finite-language-aot", Some(finite.states), Some(0))
        } else if let Some(context) = &receipt.context_determinization {
            match context.stats {
                Some(stats) => (
                    "context-determinization",
                    Some(stats.forward_states),
                    Some(stats.reverse_states),
                ),
                None => semantic_dfa_geometry(receipt.dfa),
            }
        } else {
            semantic_dfa_geometry(receipt.dfa)
        };
    AotSelectedEndCompilerEvidence {
        compiler_version: receipt.compiler_version,
        optimizer_version: receipt.optimizer_version,
        mode: format!("{:?}", receipt.mode),
        output_contract: format!("{:?}", receipt.output),
        entry_abi: format!("{:?}", receipt.entry_abi),
        target: format!("{:?}", receipt.target),
        target_feature_bits: receipt.target.features.bits(),
        line_terminator: receipt.line_terminator,
        object_sha256: hex_bytes(&receipt.object_sha256),
        engine: format!("{:?}", receipt.engine),
        engine_selection_reason: format!("{:?}", receipt.engine_selection_reason),
        determinization_decline: receipt
            .determinization
            .decline
            .as_ref()
            .map(|decline| format!("{decline:?}")),
        context_determinization_decline: receipt
            .context_determinization
            .as_ref()
            .and_then(|report| report.decline.as_ref())
            .map(|decline| format!("{decline:?}")),
        optimization_passes: receipt
            .passes
            .iter()
            .map(|pass| format!("{pass:?}"))
            .collect(),
        machine: AotSelectedEndMachineEvidence {
            state_source: state_source.to_string(),
            forward_states,
            reverse_states,
            reverse_start_recovery: receipt
                .passes
                .contains(&OptimizationPass::ReverseStartRecovery),
        },
        thompson_states: receipt.thompson_states,
        thompson_edges: receipt.thompson_edges,
        program_bytes: receipt.program_bytes,
        code_bytes: receipt.code_bytes,
        data_bytes: receipt.data_bytes,
        object_bytes: receipt.object_bytes,
    }
}

fn semantic_dfa_geometry(
    dfa: Option<fre_aot_regex::DfaStats>,
) -> (&'static str, Option<usize>, Option<usize>) {
    match dfa {
        Some(dfa) => (
            "semantic-dfa",
            Some(dfa.forward_states),
            Some(dfa.reverse_states),
        ),
        None => ("ordered-nfa-native", None, None),
    }
}

fn publication_evidence(published: &PublishedSelectedEnd) -> AotSelectedEndPublicationEvidence {
    let accounting = published.accounting();
    AotSelectedEndPublicationEvidence {
        identity_sha256: hex_bytes(published.identity().as_bytes()),
        target: format!("{:?}", published.target()),
        target_feature_bits: published.target().features.bits(),
        page_bytes: accounting.page_bytes(),
        section_count: accounting.section_count(),
        relocation_count: accounting.relocation_count(),
        code_bytes: accounting.code_bytes(),
        read_only_data_bytes: accounting.read_only_data_bytes(),
        scratch_bytes: accounting.scratch_bytes(),
        padding_bytes: accounting.padding_bytes(),
        guard_bytes: accounting.guard_bytes(),
        payload_mapped_bytes: accounting.payload_mapped_bytes(),
        total_mapped_bytes: accounting.total_mapped_bytes(),
    }
}

fn aot_search_inputs(
    authenticated: &AuthenticatedSuite,
) -> Result<Vec<AotSelectedEndSearchInput>, HoldoutError> {
    let capacity = authenticated
        .inputs
        .len()
        .checked_mul(2)
        .ok_or_else(|| HoldoutError::new("AOT window-matrix length overflow"))?;
    let mut output = Vec::new();
    output
        .try_reserve_exact(capacity)
        .map_err(|_| HoldoutError::new("allocate AOT window matrix"))?;
    for (source_index, input) in authenticated.inputs.iter().enumerate() {
        let source_haystack_sha256 = super::sha256(&input.haystack);
        output.push(AotSelectedEndSearchInput {
            source_index,
            case_id: input.case_id.clone(),
            family: input.family.clone(),
            labels: input.labels.clone(),
            pattern: input.pattern.clone(),
            input_ordinal: input.ordinal,
            declared_intent: input.intent.clone(),
            window_kind: AotSelectedEndWindowKind::Full,
            source_haystack_sha256: source_haystack_sha256.clone(),
            haystack: input.haystack.clone(),
            window_start: 0,
            window_end: input.haystack.len(),
        });
        let midscan_bytes = MIDSCAN_PREFIX
            .len()
            .checked_add(input.haystack.len())
            .and_then(|bytes| bytes.checked_add(MIDSCAN_SUFFIX.len()))
            .ok_or_else(|| HoldoutError::new("AOT midscan haystack length overflow"))?;
        let mut midscan = Vec::new();
        midscan
            .try_reserve_exact(midscan_bytes)
            .map_err(|_| HoldoutError::new("allocate AOT midscan haystack"))?;
        midscan.extend_from_slice(MIDSCAN_PREFIX);
        midscan.extend_from_slice(&input.haystack);
        midscan.extend_from_slice(MIDSCAN_SUFFIX);
        let window_end = MIDSCAN_PREFIX
            .len()
            .checked_add(input.haystack.len())
            .ok_or_else(|| HoldoutError::new("AOT midscan window overflow"))?;
        output.push(AotSelectedEndSearchInput {
            source_index,
            case_id: input.case_id.clone(),
            family: input.family.clone(),
            labels: input.labels.clone(),
            pattern: input.pattern.clone(),
            input_ordinal: input.ordinal,
            declared_intent: input.intent.clone(),
            window_kind: AotSelectedEndWindowKind::MidscanNonzeroBounded,
            source_haystack_sha256,
            haystack: midscan,
            window_start: MIDSCAN_PREFIX.len(),
            window_end,
        });
    }
    Ok(output)
}

fn aot_window_matrix_sha256(
    authenticated: &AuthenticatedSuite,
    inputs: &[AotSelectedEndSearchInput],
) -> Result<String, HoldoutError> {
    let bytes = serde_json::to_vec(&(
        AOT_SELECTED_END_WINDOW_MATRIX_SCHEMA,
        &authenticated.suite_sha256,
        &authenticated.expanded_inputs_sha256,
        inputs,
    ))
    .map_err(|error| HoldoutError::new(format!("serialize AOT window matrix: {error}")))?;
    Ok(super::sha256(&bytes))
}

const INDEPENDENT_FULL_ORACLE: &str = "regex-bytes-1.12.4-full";
const INDEPENDENT_BOUNDED_ORACLE: &str = "regex-automata-0.4.15-meta-input-span";

fn independent_oracle(pattern: &str) -> Result<IndependentOracle, HoldoutError> {
    let full = super::oracle_regex(pattern)
        .map_err(|error| HoldoutError::new(format!("build regex::bytes oracle: {error}")))?;
    let bounded = build_meta_regex(pattern)
        .map_err(|error| HoldoutError::new(format!("build bounded oracle: {error}")))?;
    Ok(IndependentOracle { full, bounded })
}

fn build_meta_regex(pattern: &str) -> Result<MetaRegex, String> {
    MetaRegex::builder()
        .configure(MetaRegex::config().utf8_empty(false))
        .syntax(syntax::Config::new().utf8(false).unicode(false))
        .build(pattern)
        .map_err(|error| error.to_string())
}

fn independent_end(
    oracle: &IndependentOracle,
    input: &AotSelectedEndSearchInput,
) -> (&'static str, Option<usize>) {
    match input.window_kind {
        AotSelectedEndWindowKind::Full => (
            INDEPENDENT_FULL_ORACLE,
            oracle
                .full
                .find(&input.haystack)
                .map(|matched| matched.end()),
        ),
        AotSelectedEndWindowKind::MidscanNonzeroBounded => (
            INDEPENDENT_BOUNDED_ORACLE,
            oracle
                .bounded
                .find(Input::new(&input.haystack).span(input.window_start..input.window_end))
                .map(|matched| matched.end()),
        ),
    }
}

fn portable_end(
    portable: &CompiledRegex,
    input: &AotSelectedEndSearchInput,
) -> Result<Option<usize>, CompileError> {
    match portable.search(
        &input.haystack,
        SearchWindow::new(input.window_start, input.window_end),
    )? {
        MatchResult::SelectedEnd(found) => Ok(found),
        MatchResult::Exists(_) | MatchResult::Span(_) => Err(CompileError::InternalInvariant(
            "SelectedEnd artifact returned a different output contract",
        )),
    }
}

#[allow(
    clippy::too_many_lines,
    reason = "portable, native, and independent terminal classification must remain one auditable transaction"
)]
fn compare_input(
    input: &AotSelectedEndSearchInput,
    independent_oracle_kind: &str,
    independent_end: Option<usize>,
    case: &AotSelectedEndCaseReceipt,
    portable: Option<&CompiledRegex>,
    published: Option<&PublishedSelectedEnd>,
) -> AotSelectedEndComparisonReceipt {
    let (
        portable_call_attempted,
        expected_end,
        actual_end,
        native_call_attempted,
        status,
        reason_code,
        reason,
    ) = match (portable, published) {
        (None, None) => (
            false,
            None,
            None,
            false,
            match case.disposition {
                AotSelectedEndDisposition::Declined => AotSelectedEndComparisonStatus::Declined,
                AotSelectedEndDisposition::Fault | AotSelectedEndDisposition::Ready => {
                    AotSelectedEndComparisonStatus::Fault
                }
            },
            case.reason_code.clone(),
            case.reason.clone(),
        ),
        (Some(portable), Some(published)) => {
            match catch_unwind(AssertUnwindSafe(|| portable_end(portable, input))) {
                Err(_) => (
                    true,
                    None,
                    None,
                    false,
                    AotSelectedEndComparisonStatus::Fault,
                    Some("portable.call.panic".to_string()),
                    Some("same-artifact portable SelectedEnd search panicked".to_string()),
                ),
                Ok(Err(error)) => (
                    true,
                    None,
                    None,
                    false,
                    AotSelectedEndComparisonStatus::Fault,
                    Some("portable.call.error".to_string()),
                    Some(error.to_string()),
                ),
                Ok(Ok(expected_end)) => {
                    match catch_unwind(AssertUnwindSafe(|| {
                        published.search(
                            &input.haystack,
                            SearchWindow::new(input.window_start, input.window_end),
                        )
                    })) {
                        Err(_) => (
                            true,
                            expected_end,
                            None,
                            true,
                            AotSelectedEndComparisonStatus::Fault,
                            Some("call.panic".to_string()),
                            Some("published AOT SelectedEnd entry panicked".to_string()),
                        ),
                        Ok(Err(error)) => (
                            true,
                            expected_end,
                            None,
                            true,
                            AotSelectedEndComparisonStatus::Fault,
                            Some(call_error_code(&error)),
                            Some(error.to_string()),
                        ),
                        Ok(Ok(actual)) if actual != expected_end => (
                            true,
                            expected_end,
                            actual,
                            true,
                            AotSelectedEndComparisonStatus::Fail,
                            Some("native-portable-semantic-mismatch".to_string()),
                            Some(format!(
                                "native AOT SelectedEnd {actual:?} differs from same-artifact portable SelectedEnd {expected_end:?}"
                            )),
                        ),
                        Ok(Ok(actual)) if expected_end != independent_end => (
                            true,
                            expected_end,
                            actual,
                            true,
                            AotSelectedEndComparisonStatus::Fail,
                            Some("portable-independent-semantic-mismatch".to_string()),
                            Some(format!(
                                "same-artifact portable SelectedEnd {expected_end:?} differs from {independent_oracle_kind} {independent_end:?}"
                            )),
                        ),
                        Ok(Ok(actual)) => (
                            true,
                            expected_end,
                            actual,
                            true,
                            AotSelectedEndComparisonStatus::Pass,
                            None,
                            None,
                        ),
                    }
                }
            }
        }
        (portable, published) => (
            portable.is_some(),
            None,
            None,
            published.is_some(),
            AotSelectedEndComparisonStatus::Fault,
            Some("case.live-artifact-closure".to_string()),
            Some(
                "portable and published artifacts did not share one ready disposition".to_string(),
            ),
        ),
    };
    AotSelectedEndComparisonReceipt {
        case_id: input.case_id.clone(),
        family: input.family.clone(),
        labels: input.labels.clone(),
        input_ordinal: input.input_ordinal,
        declared_intent: input.declared_intent.clone(),
        window_kind: input.window_kind,
        source_haystack_sha256: input.source_haystack_sha256.clone(),
        haystack_sha256: super::sha256(&input.haystack),
        haystack_bytes: input.haystack.len(),
        window_start: input.window_start,
        window_end: input.window_end,
        independent_oracle_kind: independent_oracle_kind.to_string(),
        independent_end,
        portable_call_attempted,
        expected_end,
        actual_end,
        native_call_attempted,
        status,
        reason_code,
        reason,
    }
}

fn aot_coverage(
    cases: &[AotSelectedEndCaseReceipt],
    comparisons: &[AotSelectedEndComparisonReceipt],
) -> AotSelectedEndCoverage {
    let mut coverage = AotSelectedEndCoverage {
        case_patterns: cases.len(),
        expanded_inputs: cases
            .iter()
            .fold(0, |sum, case| sum.saturating_add(case.input_count)),
        search_windows: comparisons.len(),
        ..AotSelectedEndCoverage::default()
    };
    for case in cases {
        increment(
            coverage
                .by_case_disposition
                .entry(case.disposition)
                .or_default(),
        );
    }
    for receipt in comparisons {
        if receipt.native_call_attempted {
            increment(&mut coverage.applicable_search_windows);
        }
        increment(coverage.by_input_status.entry(receipt.status).or_default());
        increment(
            coverage
                .by_window_kind_status
                .entry(receipt.window_kind)
                .or_default()
                .entry(receipt.status)
                .or_default(),
        );
        increment(
            coverage
                .by_family_input_status
                .entry(receipt.family.clone())
                .or_default()
                .entry(receipt.status)
                .or_default(),
        );
    }
    coverage
}

fn increment(value: &mut usize) {
    *value = value
        .checked_add(1)
        .expect("authenticated AOT SelectedEnd receipt counts are bounded");
}

fn compile_error_disposition(error: &CompileError) -> AotSelectedEndDisposition {
    match error {
        CompileError::Syntax(error) => syntax_error_disposition(error),
        CompileError::Resource { .. }
        | CompileError::StateExplosion { .. }
        | CompileError::Lower(
            fre_lower::LowerError::Unsupported(_)
            | fre_lower::LowerError::ResourceLimit { .. }
            | fre_lower::LowerError::Automata(fre_automata::CompileError::ResourceLimit { .. }),
        )
        | CompileError::Automaton(fre_automata::CompileError::ResourceLimit { .. })
        | CompileError::Object(ObjectError::Resource { .. }) => AotSelectedEndDisposition::Declined,
        _ => AotSelectedEndDisposition::Fault,
    }
}

#[allow(
    deprecated,
    reason = "the error vocabulary still exposes the legacy compiled-size category and the adapter must classify every category explicitly"
)]
fn syntax_error_disposition(error: &fre_syntax::ParseError) -> AotSelectedEndDisposition {
    match error.category {
        fre_syntax::ErrorCategory::FreResourceLimit { .. }
        | fre_syntax::ErrorCategory::StrictQualificationFailure { .. }
        | fre_syntax::ErrorCategory::UnsupportedNotYetImplemented { .. } => {
            AotSelectedEndDisposition::Declined
        }
        fre_syntax::ErrorCategory::InvalidPatternEncoding
        | fre_syntax::ErrorCategory::UpstreamRustSyntax
        | fre_syntax::ErrorCategory::UpstreamRustCompiledTooBig { .. }
        | fre_syntax::ErrorCategory::Re2Syntax { .. }
        | fre_syntax::ErrorCategory::InvalidConfiguration => AotSelectedEndDisposition::Fault,
    }
}

#[allow(
    deprecated,
    reason = "the error vocabulary still exposes the legacy compiled-size category and the adapter must retain a stable code for it"
)]
fn compile_error_code(error: &CompileError) -> String {
    match error {
        CompileError::Syntax(error) => match error.category {
            fre_syntax::ErrorCategory::FreResourceLimit { .. }
            | fre_syntax::ErrorCategory::StrictQualificationFailure { .. } => {
                "compile.decline.syntax-resource"
            }
            fre_syntax::ErrorCategory::UnsupportedNotYetImplemented { .. } => {
                "compile.decline.syntax-not-implemented"
            }
            fre_syntax::ErrorCategory::InvalidConfiguration => "compile.fault.syntax-profile",
            fre_syntax::ErrorCategory::InvalidPatternEncoding
            | fre_syntax::ErrorCategory::UpstreamRustSyntax
            | fre_syntax::ErrorCategory::UpstreamRustCompiledTooBig { .. }
            | fre_syntax::ErrorCategory::Re2Syntax { .. } => "compile.fault.syntax-invalid",
        },
        CompileError::Lower(fre_lower::LowerError::Unsupported(_)) => {
            "compile.decline.lower-unsupported"
        }
        CompileError::Lower(
            fre_lower::LowerError::ResourceLimit { .. }
            | fre_lower::LowerError::Automata(fre_automata::CompileError::ResourceLimit { .. }),
        ) => "compile.decline.lower-resource",
        CompileError::Lower(fre_lower::LowerError::AllocationFailed { .. }) => {
            "compile.fault.lower-allocation"
        }
        CompileError::Lower(_) => "compile.fault.lower",
        CompileError::Automaton(fre_automata::CompileError::ResourceLimit { .. }) => {
            "compile.decline.automaton-resource"
        }
        CompileError::Automaton(_) => "compile.fault.automaton",
        CompileError::Object(ObjectError::UnsupportedTarget) => {
            "compile.fault.post-host-unsupported-target"
        }
        CompileError::Object(ObjectError::Allocation(_)) => "compile.fault.object-allocation",
        CompileError::Object(ObjectError::Resource { .. }) => "compile.decline.object-resource",
        CompileError::Object(_) => "compile.fault.object",
        CompileError::Resource { resource, .. } => match resource {
            CompileResource::DfaStates => "compile.decline.dfa-states",
            CompileResource::DfaTransitions => "compile.decline.dfa-transitions",
            CompileResource::ProgramBytes => "compile.decline.program-bytes",
            CompileResource::CodeBytes => "compile.decline.code-bytes",
            CompileResource::ObjectBytes => "compile.decline.object-bytes",
            CompileResource::Work => "compile.decline.work",
        },
        CompileError::StateExplosion { .. } => "compile.decline.state-explosion",
        CompileError::Search(_) => "compile.fault.search",
        CompileError::InvalidWindow { .. } => "compile.fault.invalid-window",
        CompileError::PreparedAggregateRequiresSpan { .. } => "compile.fault.output-contract",
        CompileError::InternalInvariant(_) => "compile.fault.internal-invariant",
    }
    .to_string()
}

fn host_target_error_disposition(error: &PublicationError) -> AotSelectedEndDisposition {
    match error {
        PublicationError::UnsupportedHost => AotSelectedEndDisposition::Declined,
        _ => AotSelectedEndDisposition::Fault,
    }
}

fn host_target_error_code(error: &PublicationError) -> String {
    let suffix = match error {
        PublicationError::UnsupportedHost => "decline.unsupported-host",
        PublicationError::InvalidModule { .. } => "fault.invalid-detected-target",
        _ => "fault.impossible-host-target-stage",
    };
    format!("host-target.{suffix}")
}

fn publication_error_disposition(error: &PublicationError) -> AotSelectedEndDisposition {
    match error {
        PublicationError::Resource { .. } | PublicationError::JitDenied { .. } => {
            AotSelectedEndDisposition::Declined
        }
        _ => AotSelectedEndDisposition::Fault,
    }
}

fn publication_error_code(error: &PublicationError, prefix: &str) -> String {
    let suffix = match error {
        PublicationError::UnsupportedHost => "fault.post-host-unsupported-host",
        PublicationError::TargetMismatch { .. } => "fault.post-host-target-mismatch",
        PublicationError::CpuFeatureUnavailable { .. } => "fault.post-host-cpu-feature",
        PublicationError::RuntimeHelperRequired { .. } => "fault.runtime-helper",
        PublicationError::Resource { .. } => "decline.resource",
        PublicationError::AllocationFailed { .. } => "fault.allocation",
        PublicationError::JitDenied { .. } => "decline.jit-denied",
        PublicationError::OutputMismatch { .. } => "fault.output-mismatch",
        PublicationError::EntryAbiMismatch { .. } => "fault.entry-abi-mismatch",
        PublicationError::InvalidModule { .. } => "fault.invalid-module",
        PublicationError::ArithmeticOverflow { .. } => "fault.arithmetic-overflow",
        PublicationError::RelocationOutOfRange { .. } => "fault.relocation",
        PublicationError::CopyVerificationFailed => "fault.copy-verification",
        PublicationError::SystemCall { .. } => "fault.system-call",
        _ => "fault.unknown",
    };
    format!("{prefix}.{suffix}")
}

fn call_error_code(error: &CallError) -> String {
    match error {
        CallError::InvalidWindow { .. } => "call.fault.invalid-window",
        CallError::NativeStatus { .. } => "call.fault.native-status",
        CallError::InvalidSpan { .. } => "call.fault.invalid-end",
        _ => "call.fault.unknown",
    }
    .to_string()
}

fn hex_bytes(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut output = String::with_capacity(bytes.len().saturating_mul(2));
    for &byte in bytes {
        output.push(char::from(HEX[usize::from(byte >> 4)]));
        output.push(char::from(HEX[usize::from(byte & 0x0F)]));
    }
    output
}

fn collect_provenance() -> Result<AotSelectedEndProvenanceReceipt, HoldoutError> {
    let workspace = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .and_then(std::path::Path::parent)
        .ok_or_else(|| HoldoutError::new("resolve fre-holdout workspace root"))?
        .to_path_buf();
    let source_commit = env!("FRE_HOLDOUT_SOURCE_COMMIT").to_string();
    let current_commit = command_output_text(&workspace, "git", &["rev-parse", "HEAD"])?;
    if source_commit != current_commit {
        return Err(HoldoutError::new(format!(
            "embedded build commit is stale: embedded={source_commit:?}, current={current_commit:?}"
        )));
    }
    let build_snapshot = SourceSnapshotDigests {
        tree: env!("FRE_HOLDOUT_SOURCE_TREE").to_string(),
        status_sha256: env!("FRE_HOLDOUT_SOURCE_STATUS_SHA256").to_string(),
        diff_sha256: env!("FRE_HOLDOUT_SOURCE_DIFF_SHA256").to_string(),
        untracked_sha256: env!("FRE_HOLDOUT_SOURCE_UNTRACKED_SHA256").to_string(),
    };
    let run_snapshot = source_snapshot_digests(&workspace)?;
    verify_embedded_source_snapshot(&build_snapshot, &run_snapshot)?;
    let executable = std::env::current_exe()
        .map_err(|error| HoldoutError::new(format!("resolve current executable: {error}")))?;
    let executable_bytes = fs::read(&executable).map_err(|error| {
        HoldoutError::new(format!(
            "read current executable {}: {error}",
            executable.display()
        ))
    })?;
    Ok(AotSelectedEndProvenanceReceipt {
        source_commit,
        source_tree_at_build: build_snapshot.tree,
        source_tree_at_run: run_snapshot.tree,
        source_status_sha256_at_build: build_snapshot.status_sha256,
        source_status_sha256_at_run: run_snapshot.status_sha256,
        source_diff_sha256_at_build: build_snapshot.diff_sha256,
        source_diff_sha256_at_run: run_snapshot.diff_sha256,
        source_untracked_sha256_at_build: build_snapshot.untracked_sha256,
        source_untracked_sha256_at_run: run_snapshot.untracked_sha256,
        build_profile: env!("FRE_HOLDOUT_BUILD_PROFILE").to_string(),
        build_target: env!("FRE_HOLDOUT_BUILD_TARGET").to_string(),
        build_host: env!("FRE_HOLDOUT_BUILD_HOST").to_string(),
        rustc_version: env!("FRE_HOLDOUT_RUSTC_VERSION").to_string(),
        executable_sha256: super::sha256(&executable_bytes),
        runtime_kernel: command_output_text(&workspace, "uname", &["-a"])?,
        runtime_hostname: command_output_text(&workspace, "hostname", &[])?,
    })
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct SourceSnapshotDigests {
    tree: String,
    status_sha256: String,
    diff_sha256: String,
    untracked_sha256: String,
}

fn source_snapshot_digests(workspace: &Path) -> Result<SourceSnapshotDigests, HoldoutError> {
    source_snapshot_digests_with_git(workspace, |arguments| {
        checked_command_output_bytes(workspace, "git", arguments)
    })
}

fn source_snapshot_digests_with_git(
    workspace: &Path,
    mut git: impl FnMut(&[&str]) -> Result<Vec<u8>, HoldoutError>,
) -> Result<SourceSnapshotDigests, HoldoutError> {
    let status = git(&["status", "--porcelain=v1", "--untracked-files=all"])?;
    let diff = git(&["diff", "--no-ext-diff", "--no-textconv", "--binary", "HEAD"])?;
    let paths = git(&["ls-files", "-z", "--others", "--exclude-standard"])?;
    let untracked = untracked_source(workspace, &paths)?;
    Ok(SourceSnapshotDigests {
        tree: if status.is_empty() { "clean" } else { "dirty" }.to_string(),
        status_sha256: super::sha256(&status),
        diff_sha256: super::sha256(&diff),
        untracked_sha256: super::sha256(&untracked),
    })
}

fn verify_embedded_source_snapshot(
    build: &SourceSnapshotDigests,
    run: &SourceSnapshotDigests,
) -> Result<(), HoldoutError> {
    if build != run {
        return Err(HoldoutError::new(format!(
            "embedded build source snapshot is stale: build={build:?}, run={run:?}"
        )));
    }
    Ok(())
}

#[allow(
    clippy::unnecessary_debug_formatting,
    reason = "debug formatting preserves evidence about non-UTF-8 path bytes on a fatal read error"
)]
fn untracked_source(workspace: &Path, paths: &[u8]) -> Result<Vec<u8>, HoldoutError> {
    frame_untracked_source(paths, |relative| {
        fs::read(workspace.join(relative)).map_err(|error| {
            HoldoutError::new(format!(
                "read untracked source path {:?}: {error}",
                relative.as_os_str()
            ))
        })
    })
}

fn frame_untracked_source(
    paths: &[u8],
    mut read: impl FnMut(&Path) -> Result<Vec<u8>, HoldoutError>,
) -> Result<Vec<u8>, HoldoutError> {
    let mut output = b"\0FRE-UNTRACKED-SOURCE-V1\0".to_vec();
    for path in paths
        .split(|&byte| byte == 0)
        .filter(|path| !path.is_empty())
    {
        output.extend_from_slice(&u64::try_from(path.len()).unwrap_or(u64::MAX).to_le_bytes());
        output.extend_from_slice(path);
        let relative = git_relative_path(path)?;
        let bytes = read(&relative)?;
        output.extend_from_slice(&u64::try_from(bytes.len()).unwrap_or(u64::MAX).to_le_bytes());
        output.extend_from_slice(&bytes);
    }
    Ok(output)
}

#[cfg(unix)]
#[allow(
    clippy::unnecessary_wraps,
    reason = "the Unix byte-exact path constructor shares a fail-closed Result contract with the non-Unix UTF-8 decoder"
)]
fn git_relative_path(path: &[u8]) -> Result<PathBuf, HoldoutError> {
    Ok(PathBuf::from(OsString::from_vec(path.to_vec())))
}

#[cfg(not(unix))]
fn git_relative_path(path: &[u8]) -> Result<PathBuf, HoldoutError> {
    let path = std::str::from_utf8(path).map_err(|error| {
        HoldoutError::new(format!(
            "Git returned a non-UTF-8 untracked path on this platform: {error}"
        ))
    })?;
    Ok(PathBuf::from(path))
}

fn checked_command_output_bytes(
    directory: &Path,
    program: &str,
    arguments: &[&str],
) -> Result<Vec<u8>, HoldoutError> {
    let output = Command::new(program)
        .args(arguments)
        .current_dir(directory)
        .output()
        .map_err(|error| HoldoutError::new(format!("launch {program} {arguments:?}: {error}")))?;
    if !output.status.success() {
        return Err(HoldoutError::new(format!(
            "{program} {arguments:?} failed: status={}, stderr_bytes={}, stderr_sha256={}",
            output.status,
            output.stderr.len(),
            super::sha256(&output.stderr)
        )));
    }
    Ok(output.stdout)
}

fn command_output_text(
    directory: &Path,
    program: &str,
    arguments: &[&str],
) -> Result<String, HoldoutError> {
    let output = String::from_utf8(checked_command_output_bytes(directory, program, arguments)?)
        .map_err(|error| {
            HoldoutError::new(format!("{program} returned non-UTF-8 text: {error}"))
        })?;
    Ok(output.split_whitespace().collect::<Vec<_>>().join(" "))
}

fn target_from_receipt(receipt: &AotSelectedEndTargetReceipt) -> Result<Target, HoldoutError> {
    let architecture = match receipt.architecture.as_str() {
        "X86_64" => Architecture::X86_64,
        "Aarch64" => Architecture::Aarch64,
        other => {
            return Err(HoldoutError::new(format!(
                "unknown correctness target architecture {other:?}"
            )));
        }
    };
    let operating_system = match receipt.operating_system.as_str() {
        "Linux" => OperatingSystem::Linux,
        "Macos" => OperatingSystem::Macos,
        other => {
            return Err(HoldoutError::new(format!(
                "unknown correctness target operating system {other:?}"
            )));
        }
    };
    let abi = match receipt.abi.as_str() {
        "SystemV" => CallAbi::SystemV,
        "Aapcs64" => CallAbi::Aapcs64,
        other => {
            return Err(HoldoutError::new(format!(
                "unknown correctness target ABI {other:?}"
            )));
        }
    };
    let features = FeatureSet::from_bits(receipt.feature_bits).ok_or_else(|| {
        HoldoutError::new(format!(
            "correctness target has unknown feature bits {:#018x}",
            receipt.feature_bits
        ))
    })?;
    let target = Target::from_parts(architecture, operating_system, abi, features)
        .map_err(|error| HoldoutError::new(format!("decode correctness target: {error}")))?;
    if format!("{target:?}") != receipt.debug_identity {
        return Err(HoldoutError::new(
            "correctness target structured fields disagree with debug identity",
        ));
    }
    Ok(target)
}

fn verified_performance_target(
    host: &AotSelectedEndHostReceipt,
) -> Result<Option<Target>, HoldoutError> {
    if host.disposition != AotSelectedEndDisposition::Ready {
        return Ok(None);
    }
    let receipt = host
        .target
        .as_ref()
        .ok_or_else(|| HoldoutError::new("ready correctness host omitted target receipt"))?;
    let target = target_from_receipt(receipt)?;
    let observed = catch_unwind(AssertUnwindSafe(host_target))
        .map_err(|_| HoldoutError::new("host target revalidation panicked before timing"))?
        .map_err(|error| {
            HoldoutError::new(format!(
                "host target revalidation failed before timing: {error}"
            ))
        })?;
    if observed != target {
        return Err(HoldoutError::new(format!(
            "host target changed between correctness and timing: correctness={target:?}, timing={observed:?}"
        )));
    }
    let observed_receipt = target_receipt(observed).map_err(|failure| {
        HoldoutError::new(format!(
            "{} during timing target revalidation: {}",
            failure.code, failure.reason
        ))
    })?;
    if observed_receipt != *receipt {
        return Err(HoldoutError::new(
            "host target feature or current-thread SVE vector-length evidence changed between correctness and timing",
        ));
    }
    Ok(Some(target))
}

/// Recompute all authenticated matrices, closure rules, coverage, and digest.
#[allow(
    clippy::too_many_lines,
    reason = "one validator closes host, case, window, coverage, provenance, and digest evidence in report order"
)]
pub fn validate_aot_selected_end_correctness(
    authenticated: &AuthenticatedSuite,
    report: &AotSelectedEndCorrectnessReport,
) -> Result<(), HoldoutError> {
    if report.schema != AOT_SELECTED_END_CORRECTNESS_SCHEMA
        || report.suite_id != authenticated.manifest.suite_id
        || report.suite_sha256 != authenticated.suite_sha256
        || report.json_schema_sha256 != authenticated.json_schema_sha256
        || report.expanded_inputs_sha256 != authenticated.expanded_inputs_sha256
        || report.window_derivation != CORRECTNESS_WINDOW_DERIVATION
        || report.oracle_identity != CORRECTNESS_ORACLE_IDENTITY
        || report.candidate_identity != CORRECTNESS_CANDIDATE_IDENTITY
        || report.applicability != CORRECTNESS_APPLICABILITY
        || report.target_arch != std::env::consts::ARCH
        || report.target_os != std::env::consts::OS
        || report.target_pointer_width != usize::BITS
        || report.limit_policy != selected_end_limit_policy()
    {
        return Err(HoldoutError::new(
            "AOT SelectedEnd correctness report authentication binding is invalid",
        ));
    }
    let inputs = aot_search_inputs(authenticated)?;
    if report.window_matrix_sha256 != aot_window_matrix_sha256(authenticated, &inputs)? {
        return Err(HoldoutError::new(
            "AOT SelectedEnd correctness window-matrix digest is invalid",
        ));
    }
    if report.cases.len() != authenticated.manifest.cases.len()
        || report.comparisons.len() != inputs.len()
    {
        return Err(HoldoutError::new(
            "AOT SelectedEnd correctness matrix has the wrong dimensions",
        ));
    }
    let host_target = match report.host.disposition {
        AotSelectedEndDisposition::Ready => Some(target_from_receipt(
            report
                .host
                .target
                .as_ref()
                .ok_or_else(|| HoldoutError::new("ready host omitted target receipt"))?,
        )?),
        AotSelectedEndDisposition::Declined | AotSelectedEndDisposition::Fault => None,
    };
    match report.host.disposition {
        AotSelectedEndDisposition::Ready => {
            if report.host.target.is_none()
                || report.host.reason_code.is_some()
                || report.host.reason.is_some()
            {
                return Err(HoldoutError::new(
                    "ready host receipt has invalid target/reason closure",
                ));
            }
        }
        AotSelectedEndDisposition::Declined => {
            if report.host.target.is_some()
                || report.host.reason_code.is_none()
                || report.host.reason.is_none()
            {
                return Err(HoldoutError::new(
                    "declined host receipt has invalid target/reason closure",
                ));
            }
        }
        AotSelectedEndDisposition::Fault => {
            if report.host.reason_code.is_none() || report.host.reason.is_none() {
                return Err(HoldoutError::new("faulted host receipt omitted its reason"));
            }
            if let Some(target) = &report.host.target {
                let _ = target_from_receipt(target)?;
            }
        }
    }
    let mut cases_by_id = BTreeMap::new();
    for (spec, case) in authenticated.manifest.cases.iter().zip(&report.cases) {
        let input_count = authenticated
            .inputs
            .iter()
            .filter(|input| input.case_id == spec.id)
            .count();
        let search_window_count = inputs
            .iter()
            .filter(|input| input.case_id == spec.id)
            .count();
        if case.case_id != spec.id
            || case.family != spec.family
            || case.labels != spec.labels
            || case.pattern_sha256 != super::sha256(spec.pattern.as_bytes())
            || case.input_count != input_count
            || case.search_window_count != search_window_count
        {
            return Err(HoldoutError::new(format!(
                "case {} receipt does not close over its authenticated specification",
                spec.id
            )));
        }
        match case.disposition {
            AotSelectedEndDisposition::Ready => {
                let compiler = case.compiler.as_ref().ok_or_else(|| {
                    HoldoutError::new(format!("ready case {} omitted compiler evidence", spec.id))
                })?;
                let publication = case.publication.as_ref().ok_or_else(|| {
                    HoldoutError::new(format!(
                        "ready case {} omitted publication evidence",
                        spec.id
                    ))
                })?;
                let target = host_target.ok_or_else(|| {
                    HoldoutError::new(format!("case {} is ready behind a non-ready host", spec.id))
                })?;
                if case.terminal_stage != "ready"
                    || case.reason_code.is_some()
                    || case.reason.is_some()
                    || compiler.output_contract != "SelectedEnd"
                    || compiler.entry_abi != "SelectedEndSearchV1"
                    || compiler.target != format!("{target:?}")
                    || compiler.target_feature_bits != target.features.bits()
                    || publication.target != format!("{target:?}")
                    || publication.target_feature_bits != target.features.bits()
                    || compiler.object_sha256 != publication.identity_sha256
                {
                    return Err(HoldoutError::new(format!(
                        "ready case {} has an invalid compiler/publication closure",
                        spec.id
                    )));
                }
            }
            AotSelectedEndDisposition::Declined | AotSelectedEndDisposition::Fault => {
                if case.publication.is_some()
                    || case.reason_code.is_none()
                    || case.reason.is_none()
                    || !matches!(
                        case.terminal_stage.as_str(),
                        "host-target" | "compile" | "publish"
                    )
                    || (case.terminal_stage == "host-target" && case.compiler.is_some())
                    || (case.terminal_stage == "compile" && case.compiler.is_some())
                    || (case.terminal_stage == "publish" && case.compiler.is_none())
                    || (case.terminal_stage == "host-target"
                        && (case.disposition != report.host.disposition
                            || case.reason_code != report.host.reason_code
                            || case.reason != report.host.reason))
                {
                    return Err(HoldoutError::new(format!(
                        "non-ready case {} has an invalid terminal closure",
                        spec.id
                    )));
                }
                if let Some(compiler) = &case.compiler {
                    let target = host_target.ok_or_else(|| {
                        HoldoutError::new(format!(
                            "case {} retained compiler evidence behind a non-ready host",
                            spec.id
                        ))
                    })?;
                    if compiler.output_contract != "SelectedEnd"
                        || compiler.entry_abi != "SelectedEndSearchV1"
                        || compiler.target != format!("{target:?}")
                        || compiler.target_feature_bits != target.features.bits()
                    {
                        return Err(HoldoutError::new(format!(
                            "case {} non-ready compiler evidence has invalid target/output closure",
                            spec.id
                        )));
                    }
                }
            }
        }
        if cases_by_id.insert(case.case_id.as_str(), case).is_some() {
            return Err(HoldoutError::new("duplicate AOT case receipt"));
        }
    }
    let mut validation_oracles = BTreeMap::new();
    for spec in &authenticated.manifest.cases {
        let independent = independent_oracle(&spec.pattern).map_err(|error| {
            HoldoutError::new(format!(
                "rebuild independent oracle for {}: {error}",
                spec.id
            ))
        })?;
        let case = cases_by_id[spec.id.as_str()];
        let portable = if case.disposition == AotSelectedEndDisposition::Ready {
            let target = host_target.ok_or_else(|| {
                HoldoutError::new(format!(
                    "rebuild portable oracle for ready case {} behind non-ready host",
                    spec.id
                ))
            })?;
            Some(
                catch_unwind(AssertUnwindSafe(|| {
                    compile(selected_end_request(&spec.pattern, target))
                }))
                .map_err(|_| {
                    HoldoutError::new(format!(
                        "rebuild same-artifact portable oracle for {} panicked",
                        spec.id
                    ))
                })?
                .map_err(|error| {
                    HoldoutError::new(format!(
                        "rebuild same-artifact portable oracle for {}: {error}",
                        spec.id
                    ))
                })?,
            )
        } else {
            None
        };
        validation_oracles.insert(spec.id.as_str(), (independent, portable));
    }
    let mut ordered_inputs = Vec::new();
    for case in &authenticated.manifest.cases {
        ordered_inputs.extend(inputs.iter().filter(|input| input.case_id == case.id));
    }
    for (input, receipt) in ordered_inputs.into_iter().zip(&report.comparisons) {
        let (independent, portable) = validation_oracles
            .get(input.case_id.as_str())
            .expect("authenticated case has validation oracles");
        let (independent_oracle_kind, independent_end) = independent_end(independent, input);
        let expected_end = portable
            .as_ref()
            .map(|portable| portable_end(portable, input))
            .transpose()
            .map_err(|error| {
                HoldoutError::new(format!(
                    "recompute same-artifact portable oracle for {}:{}:{:?}: {error}",
                    input.case_id, input.input_ordinal, input.window_kind
                ))
            })?
            .flatten();
        if receipt.case_id != input.case_id
            || receipt.family != input.family
            || receipt.labels != input.labels
            || receipt.input_ordinal != input.input_ordinal
            || receipt.declared_intent != input.declared_intent
            || receipt.window_kind != input.window_kind
            || receipt.source_haystack_sha256 != input.source_haystack_sha256
            || receipt.haystack_sha256 != super::sha256(&input.haystack)
            || receipt.haystack_bytes != input.haystack.len()
            || receipt.window_start != input.window_start
            || receipt.window_end != input.window_end
            || receipt.independent_oracle_kind != independent_oracle_kind
            || receipt.independent_end != independent_end
            || receipt.expected_end != expected_end
        {
            return Err(HoldoutError::new(format!(
                "comparison {}:{}:{:?} does not close over its authenticated window",
                input.case_id, input.input_ordinal, input.window_kind
            )));
        }
        let case = cases_by_id[input.case_id.as_str()];
        match (case.disposition, receipt.status) {
            (AotSelectedEndDisposition::Ready, AotSelectedEndComparisonStatus::Pass)
                if receipt.portable_call_attempted
                    && receipt.native_call_attempted
                    && receipt.actual_end == receipt.expected_end
                    && receipt.expected_end == receipt.independent_end
                    && receipt.reason_code.is_none()
                    && receipt.reason.is_none() => {}
            (AotSelectedEndDisposition::Ready, AotSelectedEndComparisonStatus::Fail)
                if receipt.portable_call_attempted
                    && receipt.native_call_attempted
                    && (receipt.actual_end != receipt.expected_end
                        || receipt.expected_end != receipt.independent_end)
                    && receipt.reason_code.is_some()
                    && receipt.reason.is_some() => {}
            (AotSelectedEndDisposition::Ready, AotSelectedEndComparisonStatus::Fault)
                if receipt.portable_call_attempted
                    && (!receipt.native_call_attempted || receipt.actual_end.is_none())
                    && receipt.actual_end.is_none()
                    && receipt.reason_code.is_some()
                    && receipt.reason.is_some() => {}
            (AotSelectedEndDisposition::Declined, AotSelectedEndComparisonStatus::Declined)
            | (AotSelectedEndDisposition::Fault, AotSelectedEndComparisonStatus::Fault)
                if !receipt.portable_call_attempted
                    && !receipt.native_call_attempted
                    && receipt.expected_end.is_none()
                    && receipt.actual_end.is_none()
                    && receipt.reason_code == case.reason_code
                    && receipt.reason == case.reason => {}
            _ => {
                return Err(HoldoutError::new(format!(
                    "comparison {}:{}:{:?} has an invalid terminal closure",
                    input.case_id, input.input_ordinal, input.window_kind
                )));
            }
        }
    }
    let coverage = aot_coverage(&report.cases, &report.comparisons);
    if report.coverage != coverage {
        return Err(HoldoutError::new(
            "AOT SelectedEnd correctness coverage does not recompute",
        ));
    }
    let provenance_bytes = serde_json::to_vec(&(&report.host, &report.provenance))
        .map_err(|error| HoldoutError::new(format!("recompute AOT provenance digest: {error}")))?;
    if report.provenance_sha256 != super::sha256(&provenance_bytes) {
        return Err(HoldoutError::new(
            "AOT SelectedEnd provenance digest does not recompute",
        ));
    }
    let bytes = serde_json::to_vec(&(&report.limit_policy, &report.cases, &report.comparisons))
        .map_err(|error| HoldoutError::new(format!("recompute AOT correctness digest: {error}")))?;
    if report.receipts_sha256 != super::sha256(&bytes) {
        return Err(HoldoutError::new(
            "AOT SelectedEnd correctness receipt digest does not recompute",
        ));
    }
    for digest in [
        &report.provenance_sha256,
        &report.provenance.source_status_sha256_at_build,
        &report.provenance.source_status_sha256_at_run,
        &report.provenance.source_diff_sha256_at_build,
        &report.provenance.source_diff_sha256_at_run,
        &report.provenance.source_untracked_sha256_at_build,
        &report.provenance.source_untracked_sha256_at_run,
        &report.provenance.executable_sha256,
    ] {
        if digest.len() != 64 || !digest.bytes().all(|byte| byte.is_ascii_hexdigit()) {
            return Err(HoldoutError::new("invalid AOT provenance SHA-256"));
        }
    }
    if report.provenance.source_tree_at_build != report.provenance.source_tree_at_run
        || report.provenance.source_status_sha256_at_build
            != report.provenance.source_status_sha256_at_run
        || report.provenance.source_diff_sha256_at_build
            != report.provenance.source_diff_sha256_at_run
        || report.provenance.source_untracked_sha256_at_build
            != report.provenance.source_untracked_sha256_at_run
    {
        return Err(HoldoutError::new(
            "AOT provenance does not bind the executable to the runtime source snapshot",
        ));
    }
    Ok(())
}

/// Explicit engines used by the paired timing report.
#[derive(Clone, Copy, Debug, Deserialize, Serialize, Eq, Ord, PartialEq, PartialOrd)]
#[serde(rename_all = "kebab-case")]
pub enum AotSelectedEndTimingEngine {
    FreAotSelectedEndNative,
    RustRegexFindEnd,
}

/// Domain-separated schedule phase.
#[derive(Clone, Copy, Debug, Deserialize, Serialize, Eq, Ord, PartialEq, PartialOrd)]
#[serde(rename_all = "kebab-case")]
pub enum AotSelectedEndSchedulePhase {
    ColdWarmup,
    ColdMeasured,
    PublishedHotWarmup,
    PublishedHotMeasured,
}

/// One exact authenticated window position in a timing sweep.
#[derive(Clone, Debug, Deserialize, Serialize, Eq, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct AotSelectedEndScheduledInput {
    pub input_index: usize,
    pub schedule_position: usize,
    pub case_id: String,
    pub input_ordinal: usize,
    pub window_kind: AotSelectedEndWindowKind,
    pub haystack_sha256: String,
    pub window_start: usize,
    pub window_end: usize,
    pub first_engine: AotSelectedEndTimingEngine,
}

/// One complete permutation of every authenticated full/midscan input.
#[derive(Clone, Debug, Deserialize, Serialize, Eq, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct AotSelectedEndScheduledSweep {
    pub phase: AotSelectedEndSchedulePhase,
    pub repetition_index: usize,
    pub entries: Vec<AotSelectedEndScheduledInput>,
}

/// Fully recorded seeded and pair-reversal-counterbalanced schedule.
#[derive(Clone, Debug, Deserialize, Serialize, Eq, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct AotSelectedEndScheduleReceipt {
    pub schema: String,
    pub binding_sha256: String,
    pub seed_sha256: String,
    pub algorithm: String,
    pub cold_warmup: Vec<AotSelectedEndScheduledSweep>,
    pub cold_measured: Vec<AotSelectedEndScheduledSweep>,
    pub published_hot_warmup: Vec<AotSelectedEndScheduledSweep>,
    pub published_hot_measured: Vec<AotSelectedEndScheduledSweep>,
}

/// Terminal state retained for every timing observation.
#[derive(Clone, Copy, Debug, Deserialize, Serialize, Eq, Ord, PartialEq, PartialOrd)]
#[serde(rename_all = "kebab-case")]
pub enum AotSelectedEndTimingTerminal {
    Executed,
    Declined,
    Mismatch,
    Fault,
}

/// Recomputable timing-matrix and terminal coverage.
#[derive(Clone, Debug, Default, Deserialize, Serialize, Eq, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct AotSelectedEndPerformanceCoverage {
    pub authenticated_search_windows: usize,
    pub hot_setup_receipts: usize,
    pub cold_warmup_points: usize,
    pub cold_points: usize,
    pub published_hot_warmup_points: usize,
    pub published_hot_points: usize,
    pub cold_warmup_by_engine_terminal:
        BTreeMap<AotSelectedEndTimingEngine, BTreeMap<AotSelectedEndTimingTerminal, usize>>,
    pub cold_by_engine_terminal:
        BTreeMap<AotSelectedEndTimingEngine, BTreeMap<AotSelectedEndTimingTerminal, usize>>,
    pub hot_setup_by_engine_terminal:
        BTreeMap<AotSelectedEndTimingEngine, BTreeMap<AotSelectedEndTimingTerminal, usize>>,
    pub published_hot_warmup_by_engine_terminal:
        BTreeMap<AotSelectedEndTimingEngine, BTreeMap<AotSelectedEndTimingTerminal, usize>>,
    pub published_hot_by_engine_terminal:
        BTreeMap<AotSelectedEndTimingEngine, BTreeMap<AotSelectedEndTimingTerminal, usize>>,
}

/// One newly constructed matcher followed by its first scan.
#[derive(Clone, Debug, Deserialize, Serialize, Eq, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct AotSelectedEndColdObservation {
    pub terminal: AotSelectedEndTimingTerminal,
    pub compile_ns: Option<u64>,
    pub publish_ns: Option<u64>,
    pub first_scan_ns: Option<u64>,
    pub transaction_ns: Option<u64>,
    pub scan_attempted: bool,
    pub actual_end: Option<usize>,
    pub reason_code: Option<String>,
    pub reason: Option<String>,
}

/// Paired cold observation for one identical expanded input.
#[derive(Clone, Debug, Deserialize, Serialize, Eq, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct AotSelectedEndColdTimingPoint {
    pub input_index: usize,
    pub case_id: String,
    pub input_ordinal: usize,
    pub window_kind: AotSelectedEndWindowKind,
    pub source_haystack_sha256: String,
    pub haystack_sha256: String,
    pub window_start: usize,
    pub window_end: usize,
    pub repetition_index: usize,
    pub schedule_position: usize,
    pub expected_end: Option<usize>,
    pub first_engine: AotSelectedEndTimingEngine,
    pub fre_aot_selected_end_native: AotSelectedEndColdObservation,
    pub rust_regex_find_end: AotSelectedEndColdObservation,
}

/// Untimed-to-search setup retained for a published-hot case series.
#[derive(Clone, Debug, Deserialize, Serialize, Eq, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct AotSelectedEndHotSetupReceipt {
    pub engine: AotSelectedEndTimingEngine,
    pub case_id: String,
    pub terminal: AotSelectedEndTimingTerminal,
    pub compile_ns: Option<u64>,
    pub publish_ns: Option<u64>,
    pub setup_ns: Option<u64>,
    pub reason_code: Option<String>,
    pub reason: Option<String>,
}

/// One call on a matcher constructed outside the hot measurement loop.
#[derive(Clone, Debug, Deserialize, Serialize, Eq, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct AotSelectedEndHotObservation {
    pub terminal: AotSelectedEndTimingTerminal,
    pub search_ns: Option<u64>,
    pub scan_attempted: bool,
    pub actual_end: Option<usize>,
    pub reason_code: Option<String>,
    pub reason: Option<String>,
}

/// Paired hot observation for one identical expanded input.
#[derive(Clone, Debug, Deserialize, Serialize, Eq, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct AotSelectedEndHotTimingPoint {
    pub input_index: usize,
    pub case_id: String,
    pub input_ordinal: usize,
    pub window_kind: AotSelectedEndWindowKind,
    pub source_haystack_sha256: String,
    pub haystack_sha256: String,
    pub window_start: usize,
    pub window_end: usize,
    pub repetition_index: usize,
    pub schedule_position: usize,
    pub expected_end: Option<usize>,
    pub first_engine: AotSelectedEndTimingEngine,
    pub fre_aot_selected_end_native: AotSelectedEndHotObservation,
    pub rust_regex_find_end: AotSelectedEndHotObservation,
}

/// Non-normative paired timing output. It never changes correctness status.
#[derive(Clone, Debug, Deserialize, Serialize, Eq, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct AotSelectedEndPerformanceReport {
    pub schema: String,
    pub suite_id: String,
    pub suite_sha256: String,
    pub json_schema_sha256: String,
    pub expanded_inputs_sha256: String,
    pub window_matrix_sha256: String,
    pub correctness_receipts_sha256: String,
    pub correctness_provenance_sha256: String,
    pub target_arch: String,
    pub target_os: String,
    pub target_pointer_width: u32,
    pub host: AotSelectedEndHostReceipt,
    pub provenance: AotSelectedEndProvenanceReceipt,
    pub policy: TimingPolicy,
    pub limit_policy: AotSelectedEndLimitPolicyReceipt,
    pub observation_budget: AotSelectedEndObservationBudgetReceipt,
    pub normative: bool,
    pub planner_feedback_permitted: bool,
    pub candidate_identity: String,
    pub oracle_identity: String,
    pub cold_measurement_scope: String,
    pub hot_measurement_scope: String,
    pub pairing_schedule: String,
    pub readiness_floor: String,
    pub schedule: AotSelectedEndScheduleReceipt,
    pub timing_receipts_sha256: String,
    pub coverage: AotSelectedEndPerformanceCoverage,
    pub hot_setups: Vec<AotSelectedEndHotSetupReceipt>,
    pub cold_warmup_points: Vec<AotSelectedEndColdTimingPoint>,
    pub cold_points: Vec<AotSelectedEndColdTimingPoint>,
    pub published_hot_warmup_points: Vec<AotSelectedEndHotTimingPoint>,
    pub published_hot_points: Vec<AotSelectedEndHotTimingPoint>,
}

#[derive(Debug)]
struct AotHotLive {
    setup: AotSelectedEndHotSetupReceipt,
    published: Option<PublishedSelectedEnd>,
}

#[derive(Debug)]
struct RustHotLive {
    setup: AotSelectedEndHotSetupReceipt,
    regex: Option<MetaRegex>,
}

/// Run paired diagnostic timings. Cold points compile a fresh matcher for
/// every `(input, repetition)`, publish FRE in memory, and then time the first
/// scan. Hot points compile once per case outside the search samples and time
/// only calls on the reused published matcher. No portable FRE path is built
/// or timed.
#[allow(
    clippy::too_many_lines,
    reason = "the benchmark transaction and receipt schedule stay together so every timing terminal is auditable"
)]
pub fn run_aot_selected_end_performance(
    authenticated: &AuthenticatedSuite,
    correctness: &AotSelectedEndCorrectnessReport,
) -> Result<AotSelectedEndPerformanceReport, HoldoutError> {
    let live_provenance = collect_provenance()?;
    if live_provenance != correctness.provenance {
        return Err(HoldoutError::new(
            "source/build/executable provenance changed after correctness and before timing",
        ));
    }
    // These three checks deliberately precede every Instant::now() in this
    // function and its callees. A report that is not authenticated, correct,
    // and sufficiently applicable cannot enter the timing experiment.
    validate_aot_selected_end_correctness(authenticated, correctness)?;
    enforce_aot_selected_end_strict_gate(correctness)?;
    enforce_aot_selected_end_readiness_floor(correctness)?;
    validate_performance_binding(authenticated, correctness)?;
    let policy = authenticated.manifest.timing;
    // This checked ceiling deliberately precedes target revalidation, input
    // construction, schedule/receipt allocation, and every timing clock.
    let observation_budget = timing_observation_budget(
        correctness.coverage.search_windows,
        correctness.coverage.case_patterns,
        policy,
    )?;
    let target = verified_performance_target(&correctness.host)?;
    let inputs = aot_search_inputs(authenticated)?;
    let window_matrix_sha256 = aot_window_matrix_sha256(authenticated, &inputs)?;
    if window_matrix_sha256 != correctness.window_matrix_sha256 {
        return Err(HoldoutError::new(
            "AOT timing window matrix differs from the validated correctness matrix",
        ));
    }
    let expected = expected_ends(correctness, &inputs)?;
    let schedule = build_timing_schedule(
        authenticated,
        &correctness.receipts_sha256,
        &correctness.provenance_sha256,
        &window_matrix_sha256,
        &inputs,
        policy,
    )?;

    let mut cold_warmup_points = Vec::new();
    cold_warmup_points
        .try_reserve_exact(timing_point_count(
            inputs.len(),
            schedule.cold_warmup.len(),
        )?)
        .map_err(|_| HoldoutError::new("allocate cold warmup timing receipts"))?;
    let mut cold_points = Vec::new();
    cold_points
        .try_reserve_exact(timing_point_count(
            inputs.len(),
            schedule.cold_measured.len(),
        )?)
        .map_err(|_| HoldoutError::new("allocate cold measurement timing receipts"))?;
    let mut hot_setups = Vec::new();
    hot_setups
        .try_reserve_exact(
            authenticated
                .manifest
                .cases
                .len()
                .checked_mul(2)
                .ok_or_else(|| HoldoutError::new("hot setup receipt count overflow"))?,
        )
        .map_err(|_| HoldoutError::new("allocate hot setup receipts"))?;
    let mut hot_live = Vec::new();
    hot_live
        .try_reserve_exact(authenticated.manifest.cases.len())
        .map_err(|_| HoldoutError::new("allocate live hot matchers"))?;
    let mut published_hot_warmup_points = Vec::new();
    published_hot_warmup_points
        .try_reserve_exact(timing_point_count(
            inputs.len(),
            schedule.published_hot_warmup.len(),
        )?)
        .map_err(|_| HoldoutError::new("allocate hot warmup timing receipts"))?;
    let mut published_hot_points = Vec::new();
    published_hot_points
        .try_reserve_exact(timing_point_count(
            inputs.len(),
            schedule.published_hot_measured.len(),
        )?)
        .map_err(|_| HoldoutError::new("allocate hot measurement timing receipts"))?;

    for sweep in &schedule.cold_warmup {
        for entry in &sweep.entries {
            let input = scheduled_input(&inputs, entry)?;
            let expected_end = expected[entry.input_index];
            cold_warmup_points.push(run_cold_pair(
                entry.input_index,
                input,
                expected_end,
                sweep.repetition_index,
                entry.schedule_position,
                entry.first_engine,
                target,
                &correctness.host,
            ));
        }
    }
    for sweep in &schedule.cold_measured {
        for entry in &sweep.entries {
            let input = scheduled_input(&inputs, entry)?;
            cold_points.push(run_cold_pair(
                entry.input_index,
                input,
                expected[entry.input_index],
                sweep.repetition_index,
                entry.schedule_position,
                entry.first_engine,
                target,
                &correctness.host,
            ));
        }
    }

    let mut hot_case_indices = BTreeMap::new();
    for case in &authenticated.manifest.cases {
        let aot = setup_aot_hot(case, target, &correctness.host);
        let rust = setup_rust_hot(case);
        hot_setups.push(aot.setup.clone());
        hot_setups.push(rust.setup.clone());
        let index = hot_live.len();
        if hot_case_indices.insert(case.id.clone(), index).is_some() {
            return Err(HoldoutError::new("duplicate case in AOT hot setup matrix"));
        }
        hot_live.push((aot, rust));
    }
    for sweep in &schedule.published_hot_warmup {
        for entry in &sweep.entries {
            let input = scheduled_input(&inputs, entry)?;
            let (aot, rust) = hot_live
                .get(
                    *hot_case_indices
                        .get(&input.case_id)
                        .ok_or_else(|| HoldoutError::new("scheduled input omitted a hot setup"))?,
                )
                .ok_or_else(|| HoldoutError::new("scheduled hot setup index is invalid"))?;
            published_hot_warmup_points.push(run_hot_pair(
                entry.input_index,
                input,
                expected[entry.input_index],
                sweep.repetition_index,
                entry.schedule_position,
                entry.first_engine,
                aot,
                rust,
            ));
        }
    }
    for sweep in &schedule.published_hot_measured {
        for entry in &sweep.entries {
            let input = scheduled_input(&inputs, entry)?;
            let (aot, rust) = hot_live
                .get(
                    *hot_case_indices
                        .get(&input.case_id)
                        .ok_or_else(|| HoldoutError::new("scheduled input omitted a hot setup"))?,
                )
                .ok_or_else(|| HoldoutError::new("scheduled hot setup index is invalid"))?;
            published_hot_points.push(run_hot_pair(
                entry.input_index,
                input,
                expected[entry.input_index],
                sweep.repetition_index,
                entry.schedule_position,
                entry.first_engine,
                aot,
                rust,
            ));
        }
    }
    let coverage = performance_coverage(
        inputs.len(),
        &hot_setups,
        &cold_warmup_points,
        &cold_points,
        &published_hot_warmup_points,
        &published_hot_points,
    );
    let timing_receipt_bytes = serde_json::to_vec(&(
        &correctness.limit_policy,
        &observation_budget,
        &schedule,
        &hot_setups,
        &cold_warmup_points,
        &cold_points,
        &published_hot_warmup_points,
        &published_hot_points,
    ))
    .map_err(|error| HoldoutError::new(format!("serialize AOT timing receipt digest: {error}")))?;

    let report = AotSelectedEndPerformanceReport {
        schema: AOT_SELECTED_END_PERFORMANCE_SCHEMA.to_string(),
        suite_id: authenticated.manifest.suite_id.clone(),
        suite_sha256: authenticated.suite_sha256.clone(),
        json_schema_sha256: authenticated.json_schema_sha256.clone(),
        expanded_inputs_sha256: authenticated.expanded_inputs_sha256.clone(),
        window_matrix_sha256,
        correctness_receipts_sha256: correctness.receipts_sha256.clone(),
        correctness_provenance_sha256: correctness.provenance_sha256.clone(),
        target_arch: std::env::consts::ARCH.to_string(),
        target_os: std::env::consts::OS.to_string(),
        target_pointer_width: usize::BITS,
        host: correctness.host.clone(),
        provenance: correctness.provenance.clone(),
        policy,
        limit_policy: correctness.limit_policy.clone(),
        observation_budget,
        normative: false,
        planner_feedback_permitted: false,
        candidate_identity: PERFORMANCE_CANDIDATE_IDENTITY.to_string(),
        oracle_identity: PERFORMANCE_ORACLE_IDENTITY.to_string(),
        cold_measurement_scope: COLD_MEASUREMENT_SCOPE.to_string(),
        hot_measurement_scope: HOT_MEASUREMENT_SCOPE.to_string(),
        pairing_schedule: PAIRING_SCHEDULE_DESCRIPTION.to_string(),
        readiness_floor: readiness_floor_description(correctness),
        schedule,
        timing_receipts_sha256: super::sha256(&timing_receipt_bytes),
        coverage,
        hot_setups,
        cold_warmup_points,
        cold_points,
        published_hot_warmup_points,
        published_hot_points,
    };
    validate_aot_selected_end_performance(authenticated, correctness, &report)?;
    Ok(report)
}

fn validate_performance_binding(
    authenticated: &AuthenticatedSuite,
    correctness: &AotSelectedEndCorrectnessReport,
) -> Result<(), HoldoutError> {
    if correctness.schema != AOT_SELECTED_END_CORRECTNESS_SCHEMA
        || correctness.suite_id != authenticated.manifest.suite_id
        || correctness.suite_sha256 != authenticated.suite_sha256
        || correctness.json_schema_sha256 != authenticated.json_schema_sha256
        || correctness.expanded_inputs_sha256 != authenticated.expanded_inputs_sha256
        || correctness.coverage.expanded_inputs != authenticated.inputs.len()
    {
        return Err(HoldoutError::new(
            "AOT SelectedEnd performance input is not bound to this authenticated correctness report",
        ));
    }
    Ok(())
}

fn expected_ends(
    correctness: &AotSelectedEndCorrectnessReport,
    inputs: &[AotSelectedEndSearchInput],
) -> Result<Vec<Option<usize>>, HoldoutError> {
    let mut by_key = BTreeMap::new();
    for receipt in &correctness.comparisons {
        let key = (
            receipt.case_id.as_str(),
            receipt.input_ordinal,
            receipt.window_kind,
        );
        if by_key.insert(key, receipt.expected_end).is_some() {
            return Err(HoldoutError::new(
                "AOT correctness contains a duplicate expected-end window",
            ));
        }
    }
    let mut output = Vec::new();
    output
        .try_reserve_exact(inputs.len())
        .map_err(|_| HoldoutError::new("allocate AOT timing expectation vector"))?;
    for input in inputs {
        output.push(
            *by_key
                .get(&(
                    input.case_id.as_str(),
                    input.input_ordinal,
                    input.window_kind,
                ))
                .ok_or_else(|| {
                    HoldoutError::new(format!(
                        "correctness omitted timing window {}:{}:{:?}",
                        input.case_id, input.input_ordinal, input.window_kind
                    ))
                })?,
        );
    }
    if by_key.len() != output.len() {
        return Err(HoldoutError::new(
            "AOT correctness and timing expectation matrices have different cardinality",
        ));
    }
    Ok(output)
}

fn timing_point_count(windows: usize, sweeps: usize) -> Result<usize, HoldoutError> {
    windows
        .checked_mul(sweeps)
        .ok_or_else(|| HoldoutError::new("AOT timing point count overflow"))
}

fn timing_observation_budget(
    search_windows: usize,
    case_patterns: usize,
    policy: TimingPolicy,
) -> Result<AotSelectedEndObservationBudgetReceipt, HoldoutError> {
    let sweeps_per_mode = policy
        .warmup_iterations
        .checked_add(policy.measured_iterations)
        .ok_or_else(|| HoldoutError::new("AOT timing sweep count overflow"))?;
    let all_mode_sweeps = sweeps_per_mode
        .checked_mul(2)
        .ok_or_else(|| HoldoutError::new("AOT timing mode-sweep count overflow"))?;
    let planned_paired_points = search_windows
        .checked_mul(all_mode_sweeps)
        .ok_or_else(|| HoldoutError::new("AOT timing paired-point count overflow"))?;
    let planned_paired_engine_observations = planned_paired_points
        .checked_mul(2)
        .ok_or_else(|| HoldoutError::new("AOT timing paired-observation count overflow"))?;
    let planned_hot_setup_observations = case_patterns
        .checked_mul(2)
        .ok_or_else(|| HoldoutError::new("AOT timing hot-setup observation count overflow"))?;
    let planned_total_timing_observations = planned_paired_engine_observations
        .checked_add(planned_hot_setup_observations)
        .ok_or_else(|| HoldoutError::new("AOT total timing observation count overflow"))?;
    if planned_total_timing_observations > MAX_TIMING_OBSERVATIONS {
        return Err(HoldoutError::new(format!(
            "AOT timing campaign requires {planned_total_timing_observations} observations, exceeding the frozen maximum {MAX_TIMING_OBSERVATIONS}"
        )));
    }
    Ok(AotSelectedEndObservationBudgetReceipt {
        schema: AOT_SELECTED_END_OBSERVATION_BUDGET_SCHEMA.to_string(),
        maximum_timing_observations: MAX_TIMING_OBSERVATIONS,
        authenticated_search_windows: search_windows,
        authenticated_case_patterns: case_patterns,
        warmup_sweeps_per_mode: policy.warmup_iterations,
        measured_sweeps_per_mode: policy.measured_iterations,
        planned_paired_points,
        planned_paired_engine_observations,
        planned_hot_setup_observations,
        planned_total_timing_observations,
    })
}

fn build_timing_schedule(
    authenticated: &AuthenticatedSuite,
    correctness_receipts_sha256: &str,
    correctness_provenance_sha256: &str,
    window_matrix_sha256: &str,
    inputs: &[AotSelectedEndSearchInput],
    policy: TimingPolicy,
) -> Result<AotSelectedEndScheduleReceipt, HoldoutError> {
    let seed_bytes = serde_json::to_vec(&(
        AOT_SELECTED_END_SCHEDULE_SCHEMA,
        &authenticated.manifest.suite_id,
        &authenticated.suite_sha256,
        &authenticated.json_schema_sha256,
        &authenticated.expanded_inputs_sha256,
        window_matrix_sha256,
        policy,
        inputs.len(),
    ))
    .map_err(|error| HoldoutError::new(format!("serialize AOT schedule seed: {error}")))?;
    let seed_sha256 = super::sha256(&seed_bytes);
    let binding_bytes = serde_json::to_vec(&(
        AOT_SELECTED_END_SCHEDULE_SCHEMA,
        &seed_sha256,
        correctness_receipts_sha256,
        correctness_provenance_sha256,
    ))
    .map_err(|error| HoldoutError::new(format!("serialize AOT schedule binding: {error}")))?;
    let binding_sha256 = super::sha256(&binding_bytes);
    Ok(AotSelectedEndScheduleReceipt {
        schema: AOT_SELECTED_END_SCHEDULE_SCHEMA.to_string(),
        binding_sha256,
        seed_sha256: seed_sha256.clone(),
        algorithm:
            "SHA-256 domain-separated SplitMix64 Fisher-Yates; each adjacent repetition pair uses one seeded permutation then its exact reverse; every sweep contains every authenticated window once; engine-first alternates by input index, repetition, and phase"
                .to_string(),
        cold_warmup: scheduled_sweeps(
            inputs,
            AotSelectedEndSchedulePhase::ColdWarmup,
            policy.warmup_iterations,
            &seed_sha256,
        )?,
        cold_measured: scheduled_sweeps(
            inputs,
            AotSelectedEndSchedulePhase::ColdMeasured,
            policy.measured_iterations,
            &seed_sha256,
        )?,
        published_hot_warmup: scheduled_sweeps(
            inputs,
            AotSelectedEndSchedulePhase::PublishedHotWarmup,
            policy.warmup_iterations,
            &seed_sha256,
        )?,
        published_hot_measured: scheduled_sweeps(
            inputs,
            AotSelectedEndSchedulePhase::PublishedHotMeasured,
            policy.measured_iterations,
            &seed_sha256,
        )?,
    })
}

fn scheduled_sweeps(
    inputs: &[AotSelectedEndSearchInput],
    phase: AotSelectedEndSchedulePhase,
    repetitions: usize,
    seed_sha256: &str,
) -> Result<Vec<AotSelectedEndScheduledSweep>, HoldoutError> {
    let mut output = Vec::new();
    output
        .try_reserve_exact(repetitions)
        .map_err(|_| HoldoutError::new("allocate AOT scheduled sweeps"))?;
    let mut pair_permutation = Vec::new();
    for repetition_index in 0..repetitions {
        if repetition_index & 1 == 0 {
            pair_permutation = (0..inputs.len()).collect();
            let seed_bytes = serde_json::to_vec(&(
                AOT_SELECTED_END_SCHEDULE_SCHEMA,
                seed_sha256,
                phase,
                repetition_index / 2,
            ))
            .map_err(|error| HoldoutError::new(format!("serialize AOT schedule seed: {error}")))?;
            let digest = super::sha256(&seed_bytes);
            let seed = u64::from_str_radix(&digest[..16], 16)
                .map_err(|error| HoldoutError::new(format!("decode AOT schedule seed: {error}")))?;
            fisher_yates(&mut pair_permutation, ScheduleRng(seed));
        } else {
            pair_permutation.reverse();
        }
        let mut entries = Vec::new();
        entries
            .try_reserve_exact(inputs.len())
            .map_err(|_| HoldoutError::new("allocate AOT scheduled sweep entries"))?;
        for (schedule_position, &input_index) in pair_permutation.iter().enumerate() {
            let input = &inputs[input_index];
            entries.push(AotSelectedEndScheduledInput {
                input_index,
                schedule_position,
                case_id: input.case_id.clone(),
                input_ordinal: input.input_ordinal,
                window_kind: input.window_kind,
                haystack_sha256: super::sha256(&input.haystack),
                window_start: input.window_start,
                window_end: input.window_end,
                first_engine: paired_order(input_index, repetition_index, phase),
            });
        }
        output.push(AotSelectedEndScheduledSweep {
            phase,
            repetition_index,
            entries,
        });
    }
    Ok(output)
}

#[derive(Clone, Copy)]
struct ScheduleRng(u64);

impl ScheduleRng {
    fn next(&mut self) -> u64 {
        self.0 = self.0.wrapping_add(0x9e37_79b9_7f4a_7c15);
        let mut value = self.0;
        value = (value ^ (value >> 30)).wrapping_mul(0xbf58_476d_1ce4_e5b9);
        value = (value ^ (value >> 27)).wrapping_mul(0x94d0_49bb_1331_11eb);
        value ^ (value >> 31)
    }

    fn below(&mut self, upper: usize) -> usize {
        debug_assert!(upper > 0);
        let upper = u64::try_from(upper).expect("schedule length fits u64");
        let threshold = upper
            .wrapping_neg()
            .checked_rem(upper)
            .expect("schedule bound is nonzero");
        loop {
            let candidate = self.next();
            if candidate >= threshold {
                let index = candidate
                    .checked_rem(upper)
                    .expect("schedule bound is nonzero");
                return usize::try_from(index).expect("bounded index fits usize");
            }
        }
    }
}

fn fisher_yates(values: &mut [usize], mut rng: ScheduleRng) {
    for end in (1..values.len()).rev() {
        let selected = rng.below(end.checked_add(1).expect("slice index has a successor"));
        values.swap(end, selected);
    }
}

fn paired_order(
    input_index: usize,
    repetition_index: usize,
    phase: AotSelectedEndSchedulePhase,
) -> AotSelectedEndTimingEngine {
    let phase_parity = match phase {
        AotSelectedEndSchedulePhase::ColdWarmup
        | AotSelectedEndSchedulePhase::PublishedHotMeasured => 0,
        AotSelectedEndSchedulePhase::ColdMeasured
        | AotSelectedEndSchedulePhase::PublishedHotWarmup => 1,
    };
    if input_index
        .wrapping_add(repetition_index)
        .wrapping_add(phase_parity)
        & 1
        == 0
    {
        AotSelectedEndTimingEngine::FreAotSelectedEndNative
    } else {
        AotSelectedEndTimingEngine::RustRegexFindEnd
    }
}

fn scheduled_input<'a>(
    inputs: &'a [AotSelectedEndSearchInput],
    entry: &AotSelectedEndScheduledInput,
) -> Result<&'a AotSelectedEndSearchInput, HoldoutError> {
    let input = inputs
        .get(entry.input_index)
        .ok_or_else(|| HoldoutError::new("AOT schedule input index is out of range"))?;
    if entry.case_id != input.case_id
        || entry.input_ordinal != input.input_ordinal
        || entry.window_kind != input.window_kind
        || entry.haystack_sha256 != super::sha256(&input.haystack)
        || entry.window_start != input.window_start
        || entry.window_end != input.window_end
    {
        return Err(HoldoutError::new(
            "AOT schedule entry does not close over its authenticated window",
        ));
    }
    Ok(input)
}

fn performance_coverage(
    authenticated_search_windows: usize,
    hot_setups: &[AotSelectedEndHotSetupReceipt],
    cold_warmup_points: &[AotSelectedEndColdTimingPoint],
    cold_points: &[AotSelectedEndColdTimingPoint],
    hot_warmup_points: &[AotSelectedEndHotTimingPoint],
    hot_points: &[AotSelectedEndHotTimingPoint],
) -> AotSelectedEndPerformanceCoverage {
    let mut coverage = AotSelectedEndPerformanceCoverage {
        authenticated_search_windows,
        hot_setup_receipts: hot_setups.len(),
        cold_warmup_points: cold_warmup_points.len(),
        cold_points: cold_points.len(),
        published_hot_warmup_points: hot_warmup_points.len(),
        published_hot_points: hot_points.len(),
        ..AotSelectedEndPerformanceCoverage::default()
    };
    for setup in hot_setups {
        increment_timing_terminal(
            &mut coverage.hot_setup_by_engine_terminal,
            setup.engine,
            setup.terminal,
        );
    }
    for point in cold_warmup_points {
        increment_timing_terminal(
            &mut coverage.cold_warmup_by_engine_terminal,
            AotSelectedEndTimingEngine::FreAotSelectedEndNative,
            point.fre_aot_selected_end_native.terminal,
        );
        increment_timing_terminal(
            &mut coverage.cold_warmup_by_engine_terminal,
            AotSelectedEndTimingEngine::RustRegexFindEnd,
            point.rust_regex_find_end.terminal,
        );
    }
    for point in cold_points {
        increment_timing_terminal(
            &mut coverage.cold_by_engine_terminal,
            AotSelectedEndTimingEngine::FreAotSelectedEndNative,
            point.fre_aot_selected_end_native.terminal,
        );
        increment_timing_terminal(
            &mut coverage.cold_by_engine_terminal,
            AotSelectedEndTimingEngine::RustRegexFindEnd,
            point.rust_regex_find_end.terminal,
        );
    }
    for point in hot_warmup_points {
        increment_timing_terminal(
            &mut coverage.published_hot_warmup_by_engine_terminal,
            AotSelectedEndTimingEngine::FreAotSelectedEndNative,
            point.fre_aot_selected_end_native.terminal,
        );
        increment_timing_terminal(
            &mut coverage.published_hot_warmup_by_engine_terminal,
            AotSelectedEndTimingEngine::RustRegexFindEnd,
            point.rust_regex_find_end.terminal,
        );
    }
    for point in hot_points {
        increment_timing_terminal(
            &mut coverage.published_hot_by_engine_terminal,
            AotSelectedEndTimingEngine::FreAotSelectedEndNative,
            point.fre_aot_selected_end_native.terminal,
        );
        increment_timing_terminal(
            &mut coverage.published_hot_by_engine_terminal,
            AotSelectedEndTimingEngine::RustRegexFindEnd,
            point.rust_regex_find_end.terminal,
        );
    }
    coverage
}

fn increment_timing_terminal(
    counts: &mut BTreeMap<
        AotSelectedEndTimingEngine,
        BTreeMap<AotSelectedEndTimingTerminal, usize>,
    >,
    engine: AotSelectedEndTimingEngine,
    terminal: AotSelectedEndTimingTerminal,
) {
    increment(
        counts
            .entry(engine)
            .or_default()
            .entry(terminal)
            .or_default(),
    );
}

/// Recompute authentication, schedule, setup, point, terminal, coverage, and
/// digest closure for a completed timing report.
#[allow(
    clippy::too_many_lines,
    reason = "one validator closes performance metadata, all four schedule phases, setup/point matrices, terminal coverage, and digest evidence"
)]
pub fn validate_aot_selected_end_performance(
    authenticated: &AuthenticatedSuite,
    correctness: &AotSelectedEndCorrectnessReport,
    report: &AotSelectedEndPerformanceReport,
) -> Result<(), HoldoutError> {
    validate_aot_selected_end_correctness(authenticated, correctness)?;
    enforce_aot_selected_end_strict_gate(correctness)?;
    enforce_aot_selected_end_readiness_floor(correctness)?;
    validate_performance_binding(authenticated, correctness)?;
    let observation_budget = timing_observation_budget(
        correctness.coverage.search_windows,
        correctness.coverage.case_patterns,
        authenticated.manifest.timing,
    )?;
    if report.schema != AOT_SELECTED_END_PERFORMANCE_SCHEMA
        || report.suite_id != authenticated.manifest.suite_id
        || report.suite_sha256 != authenticated.suite_sha256
        || report.json_schema_sha256 != authenticated.json_schema_sha256
        || report.expanded_inputs_sha256 != authenticated.expanded_inputs_sha256
        || report.window_matrix_sha256 != correctness.window_matrix_sha256
        || report.correctness_receipts_sha256 != correctness.receipts_sha256
        || report.correctness_provenance_sha256 != correctness.provenance_sha256
        || report.target_arch != std::env::consts::ARCH
        || report.target_os != std::env::consts::OS
        || report.target_pointer_width != usize::BITS
        || report.host != correctness.host
        || report.provenance != correctness.provenance
        || report.policy != authenticated.manifest.timing
        || report.limit_policy != correctness.limit_policy
        || report.limit_policy != selected_end_limit_policy()
        || report.observation_budget != observation_budget
        || report.normative
        || report.planner_feedback_permitted
        || report.candidate_identity != PERFORMANCE_CANDIDATE_IDENTITY
        || report.oracle_identity != PERFORMANCE_ORACLE_IDENTITY
        || report.cold_measurement_scope != COLD_MEASUREMENT_SCOPE
        || report.hot_measurement_scope != HOT_MEASUREMENT_SCOPE
        || report.pairing_schedule != PAIRING_SCHEDULE_DESCRIPTION
        || report.readiness_floor != readiness_floor_description(correctness)
    {
        return Err(HoldoutError::new(
            "AOT performance report authentication/provenance binding is invalid",
        ));
    }
    let inputs = aot_search_inputs(authenticated)?;
    if report.window_matrix_sha256 != aot_window_matrix_sha256(authenticated, &inputs)? {
        return Err(HoldoutError::new(
            "AOT performance window-matrix digest is invalid",
        ));
    }
    let expected = expected_ends(correctness, &inputs)?;
    let schedule = build_timing_schedule(
        authenticated,
        &correctness.receipts_sha256,
        &correctness.provenance_sha256,
        &correctness.window_matrix_sha256,
        &inputs,
        report.policy,
    )?;
    if report.schedule != schedule {
        return Err(HoldoutError::new(
            "AOT performance schedule does not recompute exactly",
        ));
    }
    validate_hot_setup_matrix(authenticated, &report.hot_setups)?;
    validate_cold_point_matrix(
        &inputs,
        &expected,
        &report.schedule.cold_warmup,
        &report.cold_warmup_points,
    )?;
    validate_cold_point_matrix(
        &inputs,
        &expected,
        &report.schedule.cold_measured,
        &report.cold_points,
    )?;
    validate_hot_point_matrix(
        &inputs,
        &expected,
        &report.schedule.published_hot_warmup,
        &report.hot_setups,
        &report.published_hot_warmup_points,
    )?;
    validate_hot_point_matrix(
        &inputs,
        &expected,
        &report.schedule.published_hot_measured,
        &report.hot_setups,
        &report.published_hot_points,
    )?;
    let coverage = performance_coverage(
        inputs.len(),
        &report.hot_setups,
        &report.cold_warmup_points,
        &report.cold_points,
        &report.published_hot_warmup_points,
        &report.published_hot_points,
    );
    if report.coverage != coverage {
        return Err(HoldoutError::new(
            "AOT performance coverage does not recompute",
        ));
    }
    let receipt_bytes = serde_json::to_vec(&(
        &report.limit_policy,
        &report.observation_budget,
        &report.schedule,
        &report.hot_setups,
        &report.cold_warmup_points,
        &report.cold_points,
        &report.published_hot_warmup_points,
        &report.published_hot_points,
    ))
    .map_err(|error| HoldoutError::new(format!("recompute AOT timing digest: {error}")))?;
    if report.timing_receipts_sha256 != super::sha256(&receipt_bytes) {
        return Err(HoldoutError::new(
            "AOT performance timing-receipt digest does not recompute",
        ));
    }
    Ok(())
}

fn validate_hot_setup_matrix(
    authenticated: &AuthenticatedSuite,
    setups: &[AotSelectedEndHotSetupReceipt],
) -> Result<(), HoldoutError> {
    let expected_len = authenticated
        .manifest
        .cases
        .len()
        .checked_mul(2)
        .ok_or_else(|| HoldoutError::new("AOT hot setup count overflow"))?;
    if setups.len() != expected_len {
        return Err(HoldoutError::new(
            "AOT hot setup matrix has the wrong dimensions",
        ));
    }
    for (case, pair) in authenticated
        .manifest
        .cases
        .iter()
        .zip(setups.chunks_exact(2))
    {
        if pair[0].case_id != case.id
            || pair[0].engine != AotSelectedEndTimingEngine::FreAotSelectedEndNative
            || pair[1].case_id != case.id
            || pair[1].engine != AotSelectedEndTimingEngine::RustRegexFindEnd
        {
            return Err(HoldoutError::new(format!(
                "case {} hot setup pair is not exact",
                case.id
            )));
        }
        validate_hot_setup(&pair[0])?;
        validate_hot_setup(&pair[1])?;
    }
    Ok(())
}

fn validate_hot_setup(setup: &AotSelectedEndHotSetupReceipt) -> Result<(), HoldoutError> {
    if setup.engine == AotSelectedEndTimingEngine::RustRegexFindEnd && setup.publish_ns.is_some() {
        return Err(HoldoutError::new(
            "Rust regex-automata hot setup contains a publication clock",
        ));
    }
    match setup.terminal {
        AotSelectedEndTimingTerminal::Executed => {
            if setup.compile_ns.is_none()
                || setup.setup_ns.is_none()
                || (setup.engine == AotSelectedEndTimingEngine::FreAotSelectedEndNative
                    && setup.publish_ns.is_none())
                || setup.reason_code.is_some()
                || setup.reason.is_some()
            {
                return Err(HoldoutError::new(
                    "executed AOT hot setup has invalid clock/reason closure",
                ));
            }
        }
        AotSelectedEndTimingTerminal::Declined | AotSelectedEndTimingTerminal::Fault => {
            if setup.compile_ns.is_none()
                || setup.setup_ns.is_none()
                || setup.reason_code.is_none()
                || setup.reason.is_none()
                || (setup.engine == AotSelectedEndTimingEngine::RustRegexFindEnd
                    && setup.terminal == AotSelectedEndTimingTerminal::Declined)
            {
                return Err(HoldoutError::new(
                    "non-executed AOT hot setup has invalid clock/reason closure",
                ));
            }
        }
        AotSelectedEndTimingTerminal::Mismatch => {
            return Err(HoldoutError::new("hot setup cannot be a semantic mismatch"));
        }
    }
    if let Some(setup_ns) = setup.setup_ns
        && (setup.compile_ns.is_some_and(|clock| clock > setup_ns)
            || setup.publish_ns.is_some_and(|clock| clock > setup_ns))
    {
        return Err(HoldoutError::new(
            "AOT hot setup component clock exceeds its enclosing clock",
        ));
    }
    Ok(())
}

fn validate_cold_point_matrix(
    inputs: &[AotSelectedEndSearchInput],
    expected: &[Option<usize>],
    sweeps: &[AotSelectedEndScheduledSweep],
    points: &[AotSelectedEndColdTimingPoint],
) -> Result<(), HoldoutError> {
    let expected_points = inputs
        .len()
        .checked_mul(sweeps.len())
        .ok_or_else(|| HoldoutError::new("AOT cold point count overflow"))?;
    if points.len() != expected_points {
        return Err(HoldoutError::new(
            "AOT cold timing matrix has the wrong dimensions",
        ));
    }
    let mut point_iter = points.iter();
    for sweep in sweeps {
        for entry in &sweep.entries {
            let point = point_iter
                .next()
                .ok_or_else(|| HoldoutError::new("AOT cold point matrix ended early"))?;
            let input = scheduled_input(inputs, entry)?;
            validate_cold_point_identity(
                point,
                entry,
                input,
                expected[entry.input_index],
                sweep.repetition_index,
            )?;
            validate_cold_observation(
                &point.fre_aot_selected_end_native,
                point.expected_end,
                true,
            )?;
            validate_cold_observation(&point.rust_regex_find_end, point.expected_end, false)?;
        }
    }
    Ok(())
}

fn validate_cold_point_identity(
    point: &AotSelectedEndColdTimingPoint,
    entry: &AotSelectedEndScheduledInput,
    input: &AotSelectedEndSearchInput,
    expected_end: Option<usize>,
    repetition_index: usize,
) -> Result<(), HoldoutError> {
    if point.input_index != entry.input_index
        || point.case_id != input.case_id
        || point.input_ordinal != input.input_ordinal
        || point.window_kind != input.window_kind
        || point.source_haystack_sha256 != input.source_haystack_sha256
        || point.haystack_sha256 != entry.haystack_sha256
        || point.window_start != input.window_start
        || point.window_end != input.window_end
        || point.repetition_index != repetition_index
        || point.schedule_position != entry.schedule_position
        || point.expected_end != expected_end
        || point.first_engine != entry.first_engine
    {
        return Err(HoldoutError::new(
            "AOT cold point does not close over its exact scheduled tuple",
        ));
    }
    Ok(())
}

fn validate_cold_observation(
    observation: &AotSelectedEndColdObservation,
    expected_end: Option<usize>,
    aot: bool,
) -> Result<(), HoldoutError> {
    if !aot && observation.publish_ns.is_some() {
        return Err(HoldoutError::new(
            "Rust regex-automata cold observation contains a publication clock",
        ));
    }
    match observation.terminal {
        AotSelectedEndTimingTerminal::Executed => {
            if !observation.scan_attempted
                || observation.compile_ns.is_none()
                || (aot && observation.publish_ns.is_none())
                || observation.first_scan_ns.is_none()
                || observation.transaction_ns.is_none()
                || observation.actual_end != expected_end
                || observation.reason_code.is_some()
                || observation.reason.is_some()
            {
                return Err(HoldoutError::new(
                    "executed cold observation has invalid timing/result closure",
                ));
            }
        }
        AotSelectedEndTimingTerminal::Mismatch => {
            if !observation.scan_attempted
                || observation.compile_ns.is_none()
                || (aot && observation.publish_ns.is_none())
                || observation.first_scan_ns.is_none()
                || observation.transaction_ns.is_none()
                || observation.actual_end == expected_end
                || observation.reason_code.is_none()
                || observation.reason.is_none()
            {
                return Err(HoldoutError::new(
                    "mismatched cold observation has invalid timing/result closure",
                ));
            }
        }
        AotSelectedEndTimingTerminal::Declined => {
            let aot_compile_decline = aot
                && !observation.scan_attempted
                && observation.compile_ns.is_some()
                && observation.first_scan_ns.is_none()
                && observation.transaction_ns.is_some()
                && observation.actual_end.is_none();
            if !aot_compile_decline
                || observation.reason_code.is_none()
                || observation.reason.is_none()
            {
                return Err(HoldoutError::new(
                    "declined cold observation has invalid timing/result closure",
                ));
            }
        }
        AotSelectedEndTimingTerminal::Fault => {
            let scanned = observation.scan_attempted
                && observation.compile_ns.is_some()
                && (!aot || observation.publish_ns.is_some())
                && observation.first_scan_ns.is_some()
                && observation.transaction_ns.is_some();
            let stopped_early = !observation.scan_attempted
                && observation.compile_ns.is_some()
                && observation.first_scan_ns.is_none()
                && observation.transaction_ns.is_some()
                && observation.actual_end.is_none();
            if (!scanned && !stopped_early)
                || observation.reason_code.is_none()
                || observation.reason.is_none()
            {
                return Err(HoldoutError::new(
                    "faulted cold observation has invalid timing/result closure",
                ));
            }
        }
    }
    if let Some(transaction_ns) = observation.transaction_ns
        && (observation
            .compile_ns
            .is_some_and(|clock| clock > transaction_ns)
            || observation
                .publish_ns
                .is_some_and(|clock| clock > transaction_ns)
            || observation
                .first_scan_ns
                .is_some_and(|clock| clock > transaction_ns))
    {
        return Err(HoldoutError::new(
            "cold component clock exceeds its enclosing transaction clock",
        ));
    }
    Ok(())
}

fn validate_hot_point_matrix(
    inputs: &[AotSelectedEndSearchInput],
    expected: &[Option<usize>],
    sweeps: &[AotSelectedEndScheduledSweep],
    setups: &[AotSelectedEndHotSetupReceipt],
    points: &[AotSelectedEndHotTimingPoint],
) -> Result<(), HoldoutError> {
    let expected_points = inputs
        .len()
        .checked_mul(sweeps.len())
        .ok_or_else(|| HoldoutError::new("AOT hot point count overflow"))?;
    if points.len() != expected_points {
        return Err(HoldoutError::new(
            "AOT hot timing matrix has the wrong dimensions",
        ));
    }
    let setup_by_key = setups
        .iter()
        .map(|setup| ((setup.case_id.as_str(), setup.engine), setup))
        .collect::<BTreeMap<_, _>>();
    if setup_by_key.len() != setups.len() {
        return Err(HoldoutError::new("duplicate AOT hot setup receipt"));
    }
    let mut point_iter = points.iter();
    for sweep in sweeps {
        for entry in &sweep.entries {
            let point = point_iter
                .next()
                .ok_or_else(|| HoldoutError::new("AOT hot point matrix ended early"))?;
            let input = scheduled_input(inputs, entry)?;
            validate_hot_point_identity(
                point,
                entry,
                input,
                expected[entry.input_index],
                sweep.repetition_index,
            )?;
            for (engine, observation) in [
                (
                    AotSelectedEndTimingEngine::FreAotSelectedEndNative,
                    &point.fre_aot_selected_end_native,
                ),
                (
                    AotSelectedEndTimingEngine::RustRegexFindEnd,
                    &point.rust_regex_find_end,
                ),
            ] {
                let setup = setup_by_key
                    .get(&(input.case_id.as_str(), engine))
                    .ok_or_else(|| HoldoutError::new("AOT hot point omitted its setup receipt"))?;
                validate_hot_observation(observation, point.expected_end, setup)?;
            }
        }
    }
    Ok(())
}

fn validate_hot_point_identity(
    point: &AotSelectedEndHotTimingPoint,
    entry: &AotSelectedEndScheduledInput,
    input: &AotSelectedEndSearchInput,
    expected_end: Option<usize>,
    repetition_index: usize,
) -> Result<(), HoldoutError> {
    if point.input_index != entry.input_index
        || point.case_id != input.case_id
        || point.input_ordinal != input.input_ordinal
        || point.window_kind != input.window_kind
        || point.source_haystack_sha256 != input.source_haystack_sha256
        || point.haystack_sha256 != entry.haystack_sha256
        || point.window_start != input.window_start
        || point.window_end != input.window_end
        || point.repetition_index != repetition_index
        || point.schedule_position != entry.schedule_position
        || point.expected_end != expected_end
        || point.first_engine != entry.first_engine
    {
        return Err(HoldoutError::new(
            "AOT hot point does not close over its exact scheduled tuple",
        ));
    }
    Ok(())
}

fn validate_hot_observation(
    observation: &AotSelectedEndHotObservation,
    expected_end: Option<usize>,
    setup: &AotSelectedEndHotSetupReceipt,
) -> Result<(), HoldoutError> {
    if setup.terminal != AotSelectedEndTimingTerminal::Executed {
        if observation.terminal != setup.terminal
            || observation.search_ns.is_some()
            || observation.scan_attempted
            || observation.actual_end.is_some()
            || observation.reason_code != setup.reason_code
            || observation.reason != setup.reason
        {
            return Err(HoldoutError::new(
                "unavailable hot observation does not retain its setup terminal",
            ));
        }
        return Ok(());
    }
    match observation.terminal {
        AotSelectedEndTimingTerminal::Executed => {
            if observation.search_ns.is_none()
                || !observation.scan_attempted
                || observation.actual_end != expected_end
                || observation.reason_code.is_some()
                || observation.reason.is_some()
            {
                return Err(HoldoutError::new(
                    "executed hot observation has invalid result closure",
                ));
            }
        }
        AotSelectedEndTimingTerminal::Mismatch => {
            if observation.search_ns.is_none()
                || !observation.scan_attempted
                || observation.actual_end == expected_end
                || observation.reason_code.is_none()
                || observation.reason.is_none()
            {
                return Err(HoldoutError::new(
                    "mismatched hot observation has invalid result closure",
                ));
            }
        }
        AotSelectedEndTimingTerminal::Fault => {
            if observation.search_ns.is_none()
                || !observation.scan_attempted
                || observation.reason_code.is_none()
                || observation.reason.is_none()
            {
                return Err(HoldoutError::new(
                    "faulted hot observation has invalid result closure",
                ));
            }
        }
        AotSelectedEndTimingTerminal::Declined => {
            return Err(HoldoutError::new("executed hot setup declined its scan"));
        }
    }
    Ok(())
}

#[allow(
    clippy::too_many_arguments,
    reason = "the paired point receives its complete authenticated schedule tuple and exact correctness host target"
)]
fn run_cold_pair(
    input_index: usize,
    input: &AotSelectedEndSearchInput,
    expected_end: Option<usize>,
    repetition_index: usize,
    schedule_position: usize,
    first_engine: AotSelectedEndTimingEngine,
    target: Option<Target>,
    host: &AotSelectedEndHostReceipt,
) -> AotSelectedEndColdTimingPoint {
    let (aot, rust) = match first_engine {
        AotSelectedEndTimingEngine::FreAotSelectedEndNative => (
            time_aot_cold(input, expected_end, target, host),
            time_rust_cold(input, expected_end),
        ),
        AotSelectedEndTimingEngine::RustRegexFindEnd => {
            let rust = time_rust_cold(input, expected_end);
            let aot = time_aot_cold(input, expected_end, target, host);
            (aot, rust)
        }
    };
    AotSelectedEndColdTimingPoint {
        input_index,
        case_id: input.case_id.clone(),
        input_ordinal: input.input_ordinal,
        window_kind: input.window_kind,
        source_haystack_sha256: input.source_haystack_sha256.clone(),
        haystack_sha256: super::sha256(&input.haystack),
        window_start: input.window_start,
        window_end: input.window_end,
        repetition_index,
        schedule_position,
        expected_end,
        first_engine,
        fre_aot_selected_end_native: aot,
        rust_regex_find_end: rust,
    }
}

fn time_aot_cold(
    input: &AotSelectedEndSearchInput,
    expected_end: Option<usize>,
    target: Option<Target>,
    host: &AotSelectedEndHostReceipt,
) -> AotSelectedEndColdObservation {
    let Some(target) = target else {
        return cold_unavailable(host);
    };
    let transaction_started = Instant::now();
    let compile_started = Instant::now();
    let compiled = catch_unwind(AssertUnwindSafe(|| {
        compile(selected_end_request(black_box(&input.pattern), target))
    }));
    let compile_ns = elapsed_ns(compile_started);
    let compiled = match compiled {
        Err(_) => {
            let transaction_ns = elapsed_ns(transaction_started);
            return cold_early_terminal(
                transaction_ns,
                compile_ns,
                None,
                AotSelectedEndTimingTerminal::Fault,
                "cold.compile.panic",
                "AOT SelectedEnd compiler panicked",
            );
        }
        Ok(Err(error)) => {
            let transaction_ns = elapsed_ns(transaction_started);
            let terminal = disposition_terminal(compile_error_disposition(&error));
            let code = compile_error_code(&error);
            let reason = error.to_string();
            return cold_early_terminal(transaction_ns, compile_ns, None, terminal, &code, &reason);
        }
        Ok(Ok(compiled)) => compiled,
    };
    let publish_started = Instant::now();
    let published = catch_unwind(AssertUnwindSafe(|| {
        publish_selected_end(compiled, selected_end_publication_limits())
    }));
    let publish_ns = elapsed_ns(publish_started);
    let published = match published {
        Err(_) => {
            let transaction_ns = elapsed_ns(transaction_started);
            return cold_early_terminal(
                transaction_ns,
                compile_ns,
                Some(publish_ns),
                AotSelectedEndTimingTerminal::Fault,
                "cold.publish.panic",
                "in-memory AOT publication panicked",
            );
        }
        Ok(Err(error)) => {
            let transaction_ns = elapsed_ns(transaction_started);
            let terminal = disposition_terminal(publication_error_disposition(&error));
            let code = publication_error_code(&error, "cold.publish");
            let reason = error.to_string();
            return cold_early_terminal(
                transaction_ns,
                compile_ns,
                Some(publish_ns),
                terminal,
                &code,
                &reason,
            );
        }
        Ok(Ok(published)) => published,
    };
    let scan_started = Instant::now();
    let result = catch_unwind(AssertUnwindSafe(|| {
        published.search(
            black_box(&input.haystack),
            SearchWindow::new(input.window_start, input.window_end),
        )
    }));
    let first_scan_ns = elapsed_ns(scan_started);
    let transaction_ns = elapsed_ns(transaction_started);
    cold_from_native_result(
        result,
        expected_end,
        compile_ns,
        publish_ns,
        first_scan_ns,
        transaction_ns,
    )
}

fn time_rust_cold(
    input: &AotSelectedEndSearchInput,
    expected_end: Option<usize>,
) -> AotSelectedEndColdObservation {
    let transaction_started = Instant::now();
    let compile_started = Instant::now();
    let built = catch_unwind(AssertUnwindSafe(|| {
        build_meta_regex(black_box(&input.pattern))
    }));
    let compile_ns = elapsed_ns(compile_started);
    let regex = match built {
        Err(_) => {
            let transaction_ns = elapsed_ns(transaction_started);
            return cold_early_terminal(
                transaction_ns,
                compile_ns,
                None,
                AotSelectedEndTimingTerminal::Fault,
                "cold.rust.compile.panic",
                "Rust regex-automata construction panicked",
            );
        }
        Ok(Err(error)) => {
            let transaction_ns = elapsed_ns(transaction_started);
            let reason = error;
            return cold_early_terminal(
                transaction_ns,
                compile_ns,
                None,
                AotSelectedEndTimingTerminal::Fault,
                "cold.rust.compile.error",
                &reason,
            );
        }
        Ok(Ok(regex)) => regex,
    };
    let scan_started = Instant::now();
    let result = catch_unwind(AssertUnwindSafe(|| meta_span_end(&regex, black_box(input))));
    let first_scan_ns = elapsed_ns(scan_started);
    let transaction_ns = elapsed_ns(transaction_started);
    cold_from_rust_result(
        result,
        expected_end,
        compile_ns,
        first_scan_ns,
        transaction_ns,
    )
}

fn meta_span_end(regex: &MetaRegex, input: &AotSelectedEndSearchInput) -> Option<usize> {
    regex
        .find(Input::new(&input.haystack).span(input.window_start..input.window_end))
        .map(|matched| matched.end())
}

fn cold_unavailable(host: &AotSelectedEndHostReceipt) -> AotSelectedEndColdObservation {
    AotSelectedEndColdObservation {
        terminal: match host.disposition {
            AotSelectedEndDisposition::Declined => AotSelectedEndTimingTerminal::Declined,
            AotSelectedEndDisposition::Fault | AotSelectedEndDisposition::Ready => {
                AotSelectedEndTimingTerminal::Fault
            }
        },
        compile_ns: None,
        publish_ns: None,
        first_scan_ns: None,
        transaction_ns: None,
        scan_attempted: false,
        actual_end: None,
        reason_code: host
            .reason_code
            .clone()
            .or_else(|| Some("cold.fault.ready-host-without-target".to_string())),
        reason: host
            .reason
            .clone()
            .or_else(|| Some("correctness host target is unavailable".to_string())),
    }
}

fn cold_early_terminal(
    transaction_ns: u64,
    compile_ns: u64,
    publish_ns: Option<u64>,
    terminal: AotSelectedEndTimingTerminal,
    code: &str,
    reason: &str,
) -> AotSelectedEndColdObservation {
    AotSelectedEndColdObservation {
        terminal,
        compile_ns: Some(compile_ns),
        publish_ns,
        first_scan_ns: None,
        transaction_ns: Some(transaction_ns),
        scan_attempted: false,
        actual_end: None,
        reason_code: Some(code.to_string()),
        reason: Some(reason.to_string()),
    }
}

#[allow(
    clippy::needless_pass_by_value,
    reason = "the result, including any panic payload, is owned and classified exactly once"
)]
fn cold_from_native_result(
    result: Result<Result<Option<usize>, CallError>, Box<dyn std::any::Any + Send>>,
    expected_end: Option<usize>,
    compile_ns: u64,
    publish_ns: u64,
    first_scan_ns: u64,
    transaction_ns: u64,
) -> AotSelectedEndColdObservation {
    let (terminal, actual_end, reason_code, reason) = match result {
        Err(_) => (
            AotSelectedEndTimingTerminal::Fault,
            None,
            Some("cold.call.panic".to_string()),
            Some("published AOT SelectedEnd entry panicked".to_string()),
        ),
        Ok(Err(error)) => (
            AotSelectedEndTimingTerminal::Fault,
            None,
            Some(call_error_code(&error)),
            Some(error.to_string()),
        ),
        Ok(Ok(actual)) if actual == expected_end => {
            (AotSelectedEndTimingTerminal::Executed, actual, None, None)
        }
        Ok(Ok(actual)) => (
            AotSelectedEndTimingTerminal::Mismatch,
            actual,
            Some("cold.semantic-mismatch".to_string()),
            Some(format!("actual {actual:?}, expected {expected_end:?}")),
        ),
    };
    AotSelectedEndColdObservation {
        terminal,
        compile_ns: Some(compile_ns),
        publish_ns: Some(publish_ns),
        first_scan_ns: Some(first_scan_ns),
        transaction_ns: Some(transaction_ns),
        scan_attempted: true,
        actual_end,
        reason_code,
        reason,
    }
}

#[allow(
    clippy::needless_pass_by_value,
    reason = "the result, including any panic payload, is owned and classified exactly once"
)]
fn cold_from_rust_result(
    result: Result<Option<usize>, Box<dyn std::any::Any + Send>>,
    expected_end: Option<usize>,
    compile_ns: u64,
    first_scan_ns: u64,
    transaction_ns: u64,
) -> AotSelectedEndColdObservation {
    let (terminal, actual_end, reason_code, reason) = match result {
        Err(_) => (
            AotSelectedEndTimingTerminal::Fault,
            None,
            Some("cold.rust.call.panic".to_string()),
            Some("Rust regex-automata span search panicked".to_string()),
        ),
        Ok(actual) if actual == expected_end => {
            (AotSelectedEndTimingTerminal::Executed, actual, None, None)
        }
        Ok(actual) => (
            AotSelectedEndTimingTerminal::Mismatch,
            actual,
            Some("cold.rust.semantic-mismatch".to_string()),
            Some(format!("actual {actual:?}, expected {expected_end:?}")),
        ),
    };
    AotSelectedEndColdObservation {
        terminal,
        compile_ns: Some(compile_ns),
        publish_ns: None,
        first_scan_ns: Some(first_scan_ns),
        transaction_ns: Some(transaction_ns),
        scan_attempted: true,
        actual_end,
        reason_code,
        reason,
    }
}

#[allow(
    clippy::too_many_lines,
    reason = "setup owns the complete compile/publication terminal classification for one audit receipt"
)]
fn setup_aot_hot(
    case: &CaseSpec,
    target: Option<Target>,
    host: &AotSelectedEndHostReceipt,
) -> AotHotLive {
    let Some(target) = target else {
        return AotHotLive {
            setup: hot_setup_from_host(case, host),
            published: None,
        };
    };
    let setup_started = Instant::now();
    let compile_started = Instant::now();
    let compiled = catch_unwind(AssertUnwindSafe(|| {
        compile(selected_end_request(&case.pattern, target))
    }));
    let compile_ns = elapsed_ns(compile_started);
    let compiled = match compiled {
        Err(_) => {
            let setup_ns = elapsed_ns(setup_started);
            return AotHotLive {
                setup: hot_setup_terminal(
                    AotSelectedEndTimingEngine::FreAotSelectedEndNative,
                    case,
                    AotSelectedEndTimingTerminal::Fault,
                    Some(compile_ns),
                    None,
                    Some(setup_ns),
                    "hot.compile.panic",
                    "AOT SelectedEnd compiler panicked",
                ),
                published: None,
            };
        }
        Ok(Err(error)) => {
            let setup_ns = elapsed_ns(setup_started);
            let terminal = disposition_terminal(compile_error_disposition(&error));
            let code = compile_error_code(&error);
            let reason = error.to_string();
            return AotHotLive {
                setup: hot_setup_terminal(
                    AotSelectedEndTimingEngine::FreAotSelectedEndNative,
                    case,
                    terminal,
                    Some(compile_ns),
                    None,
                    Some(setup_ns),
                    &code,
                    &reason,
                ),
                published: None,
            };
        }
        Ok(Ok(compiled)) => compiled,
    };
    let publish_started = Instant::now();
    let published = catch_unwind(AssertUnwindSafe(|| {
        publish_selected_end(compiled, selected_end_publication_limits())
    }));
    let publish_ns = elapsed_ns(publish_started);
    let published = match published {
        Err(_) => {
            let setup_ns = elapsed_ns(setup_started);
            return AotHotLive {
                setup: hot_setup_terminal(
                    AotSelectedEndTimingEngine::FreAotSelectedEndNative,
                    case,
                    AotSelectedEndTimingTerminal::Fault,
                    Some(compile_ns),
                    Some(publish_ns),
                    Some(setup_ns),
                    "hot.publish.panic",
                    "in-memory AOT publication panicked",
                ),
                published: None,
            };
        }
        Ok(Err(error)) => {
            let setup_ns = elapsed_ns(setup_started);
            let terminal = disposition_terminal(publication_error_disposition(&error));
            let code = publication_error_code(&error, "hot.publish");
            let reason = error.to_string();
            return AotHotLive {
                setup: hot_setup_terminal(
                    AotSelectedEndTimingEngine::FreAotSelectedEndNative,
                    case,
                    terminal,
                    Some(compile_ns),
                    Some(publish_ns),
                    Some(setup_ns),
                    &code,
                    &reason,
                ),
                published: None,
            };
        }
        Ok(Ok(published)) => published,
    };
    let setup_ns = elapsed_ns(setup_started);
    AotHotLive {
        setup: AotSelectedEndHotSetupReceipt {
            engine: AotSelectedEndTimingEngine::FreAotSelectedEndNative,
            case_id: case.id.clone(),
            terminal: AotSelectedEndTimingTerminal::Executed,
            compile_ns: Some(compile_ns),
            publish_ns: Some(publish_ns),
            setup_ns: Some(setup_ns),
            reason_code: None,
            reason: None,
        },
        published: Some(published),
    }
}

fn hot_setup_from_host(
    case: &CaseSpec,
    host: &AotSelectedEndHostReceipt,
) -> AotSelectedEndHotSetupReceipt {
    AotSelectedEndHotSetupReceipt {
        engine: AotSelectedEndTimingEngine::FreAotSelectedEndNative,
        case_id: case.id.clone(),
        terminal: match host.disposition {
            AotSelectedEndDisposition::Declined => AotSelectedEndTimingTerminal::Declined,
            AotSelectedEndDisposition::Fault | AotSelectedEndDisposition::Ready => {
                AotSelectedEndTimingTerminal::Fault
            }
        },
        compile_ns: None,
        publish_ns: None,
        setup_ns: None,
        reason_code: host
            .reason_code
            .clone()
            .or_else(|| Some("hot.fault.ready-host-without-target".to_string())),
        reason: host
            .reason
            .clone()
            .or_else(|| Some("correctness host target is unavailable".to_string())),
    }
}

fn setup_rust_hot(case: &CaseSpec) -> RustHotLive {
    let setup_started = Instant::now();
    let built = catch_unwind(AssertUnwindSafe(|| build_meta_regex(&case.pattern)));
    let compile_ns = elapsed_ns(setup_started);
    match built {
        Err(_) => RustHotLive {
            setup: hot_setup_terminal(
                AotSelectedEndTimingEngine::RustRegexFindEnd,
                case,
                AotSelectedEndTimingTerminal::Fault,
                Some(compile_ns),
                None,
                Some(compile_ns),
                "hot.rust.compile.panic",
                "Rust regex-automata construction panicked",
            ),
            regex: None,
        },
        Ok(Err(error)) => RustHotLive {
            setup: hot_setup_terminal(
                AotSelectedEndTimingEngine::RustRegexFindEnd,
                case,
                AotSelectedEndTimingTerminal::Fault,
                Some(compile_ns),
                None,
                Some(compile_ns),
                "hot.rust.compile.error",
                &error,
            ),
            regex: None,
        },
        Ok(Ok(regex)) => RustHotLive {
            setup: AotSelectedEndHotSetupReceipt {
                engine: AotSelectedEndTimingEngine::RustRegexFindEnd,
                case_id: case.id.clone(),
                terminal: AotSelectedEndTimingTerminal::Executed,
                compile_ns: Some(compile_ns),
                publish_ns: None,
                setup_ns: Some(compile_ns),
                reason_code: None,
                reason: None,
            },
            regex: Some(regex),
        },
    }
}

#[allow(
    clippy::too_many_arguments,
    reason = "the setup receipt keeps every independently nullable clock and failure field explicit"
)]
fn hot_setup_terminal(
    engine: AotSelectedEndTimingEngine,
    case: &CaseSpec,
    terminal: AotSelectedEndTimingTerminal,
    compile_ns: Option<u64>,
    publish_ns: Option<u64>,
    setup_ns: Option<u64>,
    code: &str,
    reason: &str,
) -> AotSelectedEndHotSetupReceipt {
    AotSelectedEndHotSetupReceipt {
        engine,
        case_id: case.id.clone(),
        terminal,
        compile_ns,
        publish_ns,
        setup_ns,
        reason_code: Some(code.to_string()),
        reason: Some(reason.to_string()),
    }
}

#[allow(
    clippy::too_many_arguments,
    reason = "the paired point receives its complete authenticated schedule tuple and both prebuilt matcher receipts"
)]
fn run_hot_pair(
    input_index: usize,
    input: &AotSelectedEndSearchInput,
    expected_end: Option<usize>,
    repetition_index: usize,
    schedule_position: usize,
    first_engine: AotSelectedEndTimingEngine,
    aot: &AotHotLive,
    rust: &RustHotLive,
) -> AotSelectedEndHotTimingPoint {
    let (aot_observation, rust_observation) = match first_engine {
        AotSelectedEndTimingEngine::FreAotSelectedEndNative => (
            time_aot_hot(aot, input, expected_end),
            time_rust_hot(rust, input, expected_end),
        ),
        AotSelectedEndTimingEngine::RustRegexFindEnd => {
            let rust_observation = time_rust_hot(rust, input, expected_end);
            let aot_observation = time_aot_hot(aot, input, expected_end);
            (aot_observation, rust_observation)
        }
    };
    AotSelectedEndHotTimingPoint {
        input_index,
        case_id: input.case_id.clone(),
        input_ordinal: input.input_ordinal,
        window_kind: input.window_kind,
        source_haystack_sha256: input.source_haystack_sha256.clone(),
        haystack_sha256: super::sha256(&input.haystack),
        window_start: input.window_start,
        window_end: input.window_end,
        repetition_index,
        schedule_position,
        expected_end,
        first_engine,
        fre_aot_selected_end_native: aot_observation,
        rust_regex_find_end: rust_observation,
    }
}

fn time_aot_hot(
    live: &AotHotLive,
    input: &AotSelectedEndSearchInput,
    expected_end: Option<usize>,
) -> AotSelectedEndHotObservation {
    let Some(published) = &live.published else {
        return hot_from_setup(&live.setup);
    };
    let started = Instant::now();
    let result = catch_unwind(AssertUnwindSafe(|| {
        published.search(
            black_box(&input.haystack),
            SearchWindow::new(input.window_start, input.window_end),
        )
    }));
    let search_ns = elapsed_ns(started);
    match result {
        Err(_) => hot_terminal(
            AotSelectedEndTimingTerminal::Fault,
            search_ns,
            None,
            "hot.call.panic",
            "published AOT SelectedEnd entry panicked",
        ),
        Ok(Err(error)) => hot_terminal(
            AotSelectedEndTimingTerminal::Fault,
            search_ns,
            None,
            &call_error_code(&error),
            &error.to_string(),
        ),
        Ok(Ok(actual)) if actual == expected_end => AotSelectedEndHotObservation {
            terminal: AotSelectedEndTimingTerminal::Executed,
            search_ns: Some(search_ns),
            scan_attempted: true,
            actual_end: actual,
            reason_code: None,
            reason: None,
        },
        Ok(Ok(actual)) => hot_terminal(
            AotSelectedEndTimingTerminal::Mismatch,
            search_ns,
            actual,
            "hot.semantic-mismatch",
            &format!("actual {actual:?}, expected {expected_end:?}"),
        ),
    }
}

fn time_rust_hot(
    live: &RustHotLive,
    input: &AotSelectedEndSearchInput,
    expected_end: Option<usize>,
) -> AotSelectedEndHotObservation {
    let Some(regex) = &live.regex else {
        return hot_from_setup(&live.setup);
    };
    let started = Instant::now();
    let result = catch_unwind(AssertUnwindSafe(|| meta_span_end(regex, black_box(input))));
    let search_ns = elapsed_ns(started);
    match result {
        Err(_) => hot_terminal(
            AotSelectedEndTimingTerminal::Fault,
            search_ns,
            None,
            "hot.rust.call.panic",
            "Rust regex-automata span search panicked",
        ),
        Ok(actual) if actual == expected_end => AotSelectedEndHotObservation {
            terminal: AotSelectedEndTimingTerminal::Executed,
            search_ns: Some(search_ns),
            scan_attempted: true,
            actual_end: actual,
            reason_code: None,
            reason: None,
        },
        Ok(actual) => hot_terminal(
            AotSelectedEndTimingTerminal::Mismatch,
            search_ns,
            actual,
            "hot.rust.semantic-mismatch",
            &format!("actual {actual:?}, expected {expected_end:?}"),
        ),
    }
}

fn hot_from_setup(setup: &AotSelectedEndHotSetupReceipt) -> AotSelectedEndHotObservation {
    AotSelectedEndHotObservation {
        terminal: setup.terminal,
        search_ns: None,
        scan_attempted: false,
        actual_end: None,
        reason_code: setup.reason_code.clone(),
        reason: setup.reason.clone(),
    }
}

fn hot_terminal(
    terminal: AotSelectedEndTimingTerminal,
    search_ns: u64,
    actual_end: Option<usize>,
    code: &str,
    reason: &str,
) -> AotSelectedEndHotObservation {
    AotSelectedEndHotObservation {
        terminal,
        search_ns: Some(search_ns),
        scan_attempted: true,
        actual_end,
        reason_code: Some(code.to_string()),
        reason: Some(reason.to_string()),
    }
}

fn disposition_terminal(disposition: AotSelectedEndDisposition) -> AotSelectedEndTimingTerminal {
    match disposition {
        AotSelectedEndDisposition::Ready => AotSelectedEndTimingTerminal::Executed,
        AotSelectedEndDisposition::Declined => AotSelectedEndTimingTerminal::Declined,
        AotSelectedEndDisposition::Fault => AotSelectedEndTimingTerminal::Fault,
    }
}

fn elapsed_ns(started: Instant) -> u64 {
    u64::try_from(started.elapsed().as_nanos()).unwrap_or(u64::MAX)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        DimensionDeclaration, ExplicitInput, GeneratorSpec, OracleDeclaration, SuiteManifest,
        expand_manifest,
    };

    fn fixture(timing: TimingPolicy) -> AuthenticatedSuite {
        let manifest = SuiteManifest {
            schema: "fre.holdout.suite.v1".to_string(),
            suite_id: "aot-selected-end-fixture".to_string(),
            freeze_date: "2026-07-14".to_string(),
            oracle: OracleDeclaration {
                implementation: "rust-regex".to_string(),
                version: "1.12.4".to_string(),
                api: "bytes".to_string(),
                unicode: false,
            },
            timing,
            dimensions: Vec::<DimensionDeclaration>::new(),
            cases: vec![CaseSpec {
                id: "literal".to_string(),
                family: "test".to_string(),
                labels: vec!["positive-negative".to_string()],
                pattern: "needle".to_string(),
                generator: GeneratorSpec::Explicit {
                    inputs: vec![
                        ExplicitInput {
                            hex: "78786e6565646c657979".to_string(),
                            intent: "positive".to_string(),
                        },
                        ExplicitInput {
                            hex: "6e6f7468696e67".to_string(),
                            intent: "negative".to_string(),
                        },
                    ],
                },
            }],
        };
        let inputs = expand_manifest(&manifest).expect("expand AOT fixture");
        AuthenticatedSuite {
            manifest,
            inputs,
            suite_sha256: "fixture-suite".to_string(),
            json_schema_sha256: "fixture-schema".to_string(),
            expanded_inputs_sha256: "fixture-expanded".to_string(),
        }
    }

    #[test]
    fn aot_selected_end_correctness_uses_published_native_entry_for_every_fixture_input() {
        let authenticated = fixture(TimingPolicy {
            warmup_iterations: 0,
            measured_iterations: 1,
        });
        let report = run_aot_selected_end_correctness(&authenticated)
            .expect("run fixture native AOT correctness");
        assert_eq!(report.schema, AOT_SELECTED_END_CORRECTNESS_SCHEMA);
        assert_eq!(report.coverage.case_patterns, 1);
        assert_eq!(report.coverage.expanded_inputs, 2);
        assert_eq!(report.coverage.search_windows, 4);
        assert_eq!(report.coverage.applicable_search_windows, 4);
        assert_eq!(
            report
                .coverage
                .by_case_disposition
                .get(&AotSelectedEndDisposition::Ready),
            Some(&1)
        );
        assert_eq!(
            report
                .coverage
                .by_input_status
                .get(&AotSelectedEndComparisonStatus::Pass),
            Some(&4)
        );
        assert_eq!(
            report
                .comparisons
                .iter()
                .filter(|receipt| receipt.window_kind == AotSelectedEndWindowKind::Full)
                .count(),
            2
        );
        let midscan = report
            .comparisons
            .iter()
            .filter(|receipt| {
                receipt.window_kind == AotSelectedEndWindowKind::MidscanNonzeroBounded
            })
            .collect::<Vec<_>>();
        assert_eq!(midscan.len(), 2);
        assert!(midscan.iter().all(|receipt| {
            receipt.window_start > 0
                && receipt.window_end < receipt.haystack_bytes
                && receipt.haystack_sha256 != receipt.source_haystack_sha256
        }));
        assert!(
            report
                .comparisons
                .iter()
                .all(|receipt| receipt.native_call_attempted)
        );
        let compiler = report.cases[0]
            .compiler
            .as_ref()
            .expect("compiler evidence");
        assert_eq!(compiler.output_contract, "SelectedEnd");
        assert_eq!(compiler.entry_abi, "SelectedEndSearchV1");
        assert!(!compiler.machine.reverse_start_recovery);
        assert_eq!(report.limit_policy, selected_end_limit_policy());
        assert_eq!(
            report.cases[0]
                .publication
                .as_ref()
                .expect("publication evidence")
                .identity_sha256,
            compiler.object_sha256
        );
        assert!(report.candidate_identity.contains("no portable executor"));
        validate_aot_selected_end_correctness(&authenticated, &report)
            .expect("fixture correctness closure");
        enforce_aot_selected_end_strict_gate(&report).expect("fixture strict gate");
    }

    #[test]
    fn aot_selected_end_performance_keeps_cold_and_published_hot_boundaries_separate() {
        let authenticated = fixture(TimingPolicy {
            warmup_iterations: 0,
            measured_iterations: 1,
        });
        let correctness = run_aot_selected_end_correctness(&authenticated)
            .expect("run fixture native AOT correctness");
        let performance = run_aot_selected_end_performance(&authenticated, &correctness)
            .expect("run tiny paired timing fixture");
        assert_eq!(performance.schema, AOT_SELECTED_END_PERFORMANCE_SCHEMA);
        assert_eq!(performance.cold_points.len(), 4);
        assert_eq!(performance.published_hot_points.len(), 4);
        assert_eq!(performance.hot_setups.len(), 2);
        assert_eq!(performance.limit_policy, selected_end_limit_policy());
        assert_eq!(
            performance
                .observation_budget
                .planned_total_timing_observations,
            18
        );
        assert!(
            performance
                .candidate_identity
                .contains("no portable FRE fallback")
        );
        for point in &performance.cold_points {
            let aot = &point.fre_aot_selected_end_native;
            assert_eq!(aot.terminal, AotSelectedEndTimingTerminal::Executed);
            assert!(aot.compile_ns.is_some());
            assert!(aot.publish_ns.is_some());
            assert!(aot.first_scan_ns.is_some());
            assert!(aot.transaction_ns.is_some());
            let rust = &point.rust_regex_find_end;
            assert_eq!(rust.terminal, AotSelectedEndTimingTerminal::Executed);
            assert!(rust.compile_ns.is_some());
            assert!(rust.publish_ns.is_none());
            assert!(rust.first_scan_ns.is_some());
        }
        for point in &performance.published_hot_points {
            assert!(point.fre_aot_selected_end_native.search_ns.is_some());
            assert!(point.rust_regex_find_end.search_ns.is_some());
        }
        assert_eq!(
            performance
                .cold_points
                .iter()
                .filter(|point| {
                    point.window_kind == AotSelectedEndWindowKind::MidscanNonzeroBounded
                })
                .count(),
            2
        );
        validate_aot_selected_end_performance(&authenticated, &correctness, &performance)
            .expect("fixture performance closure");
        let mut tampered = performance.clone();
        tampered.cold_points[0].schedule_position ^= 1;
        assert!(
            validate_aot_selected_end_performance(&authenticated, &correctness, &tampered).is_err()
        );
        assert!(!performance.normative);
        assert!(!performance.planner_feedback_permitted);
        let mut resource_tamper = performance;
        resource_tamper
            .observation_budget
            .maximum_timing_observations += 1;
        assert!(
            validate_aot_selected_end_performance(&authenticated, &correctness, &resource_tamper)
                .is_err()
        );
    }

    #[test]
    fn readiness_floor_requires_both_window_kinds_for_each_ready_case() {
        let authenticated = fixture(TimingPolicy {
            warmup_iterations: 0,
            measured_iterations: 1,
        });
        let mut report = run_aot_selected_end_correctness(&authenticated)
            .expect("run fixture native AOT correctness");
        let mut uncovered_case = report.cases[0].clone();
        uncovered_case.case_id = "aggregate-only-ready".to_string();
        report.cases.push(uncovered_case);
        report.coverage.case_patterns = 2;
        report
            .coverage
            .by_case_disposition
            .insert(AotSelectedEndDisposition::Ready, 2);
        // The original case alone contributes two Pass receipts of each kind,
        // so the old aggregate >= ready_cases check accepted this skew.
        assert_eq!(
            report.coverage.by_window_kind_status[&AotSelectedEndWindowKind::Full]
                [&AotSelectedEndComparisonStatus::Pass],
            2
        );
        assert_eq!(
            report.coverage.by_window_kind_status[&AotSelectedEndWindowKind::MidscanNonzeroBounded]
                [&AotSelectedEndComparisonStatus::Pass],
            2
        );
        assert!(enforce_aot_selected_end_readiness_floor(&report).is_err());

        for window_kind in [
            AotSelectedEndWindowKind::Full,
            AotSelectedEndWindowKind::MidscanNonzeroBounded,
        ] {
            let mut comparison = report
                .comparisons
                .iter()
                .find(|receipt| receipt.window_kind == window_kind)
                .expect("fixture comparison for each window kind")
                .clone();
            comparison.case_id = "aggregate-only-ready".to_string();
            report.comparisons.push(comparison);
        }
        enforce_aot_selected_end_readiness_floor(&report)
            .expect("one Pass of each window kind closes every ready case");
    }

    #[test]
    fn effective_limits_and_timing_observation_ceiling_are_frozen() {
        let target = host_target().expect("supported native host target");
        let request = selected_end_request("needle", target);
        assert_eq!(request.limits, selected_end_compile_limits());
        assert_eq!(
            selected_end_limit_policy().compile.max_program_bytes,
            10 * (1 << 20)
        );
        assert_eq!(
            selected_end_limit_policy().publication.max_mapped_bytes,
            1_073_741_824
        );
        let frozen = timing_observation_budget(
            338,
            19,
            TimingPolicy {
                warmup_iterations: 3,
                measured_iterations: 9,
            },
        )
        .expect("frozen campaign fits the explicit ceiling");
        assert_eq!(frozen.planned_paired_points, 8_112);
        assert_eq!(frozen.planned_total_timing_observations, 16_262);
        assert_eq!(frozen.maximum_timing_observations, 65_536);
        assert!(
            timing_observation_budget(
                338,
                19,
                TimingPolicy {
                    warmup_iterations: 3,
                    measured_iterations: 100,
                },
            )
            .is_err()
        );
        assert!(
            timing_observation_budget(
                usize::MAX,
                19,
                TimingPolicy {
                    warmup_iterations: 1,
                    measured_iterations: 1,
                },
            )
            .is_err()
        );
    }

    #[test]
    fn performance_rejects_observation_cap_before_campaign() {
        let authenticated = fixture(TimingPolicy {
            warmup_iterations: 0,
            measured_iterations: 10_000,
        });
        let correctness = run_aot_selected_end_correctness(&authenticated)
            .expect("correctness remains independent of timing cardinality");
        let error = run_aot_selected_end_performance(&authenticated, &correctness)
            .expect_err("oversized timing campaign must be rejected");
        assert!(error.to_string().contains("exceeding the frozen maximum"));
    }

    #[test]
    fn embedded_git_provenance_matches_current_worktree() {
        let workspace = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .parent()
            .and_then(std::path::Path::parent)
            .expect("fre-holdout workspace root")
            .to_path_buf();
        assert_eq!(
            env!("FRE_HOLDOUT_SOURCE_COMMIT"),
            command_output_text(&workspace, "git", &["rev-parse", "HEAD"])
                .expect("read current Git commit as UTF-8")
        );
        let current =
            source_snapshot_digests(&workspace).expect("capture current worktree source snapshot");
        let embedded = SourceSnapshotDigests {
            tree: env!("FRE_HOLDOUT_SOURCE_TREE").to_string(),
            status_sha256: env!("FRE_HOLDOUT_SOURCE_STATUS_SHA256").to_string(),
            diff_sha256: env!("FRE_HOLDOUT_SOURCE_DIFF_SHA256").to_string(),
            untracked_sha256: env!("FRE_HOLDOUT_SOURCE_UNTRACKED_SHA256").to_string(),
        };
        verify_embedded_source_snapshot(&embedded, &current)
            .expect("embedded source snapshot matches current worktree exactly");
    }

    #[test]
    fn stale_dirty_patch_a_is_rejected_after_dirty_patch_b_replaces_it() {
        let patch_a = SourceSnapshotDigests {
            tree: "dirty".to_string(),
            status_sha256: "11".repeat(32),
            diff_sha256: "22".repeat(32),
            untracked_sha256: "33".repeat(32),
        };
        let mut patch_b = patch_a.clone();
        patch_b.diff_sha256 = "44".repeat(32);
        assert!(verify_embedded_source_snapshot(&patch_a, &patch_b).is_err());
        assert!(verify_embedded_source_snapshot(&patch_b, &patch_b).is_ok());
    }

    #[test]
    fn git_snapshot_command_failures_cannot_become_dirty_a_or_b_evidence() {
        let workspace = Path::new(".");
        for failed_command in ["status", "diff", "ls-files"] {
            for patch in [b"dirty patch A".as_slice(), b"dirty patch B".as_slice()] {
                let error = source_snapshot_digests_with_git(workspace, |arguments| {
                    if arguments.first() == Some(&failed_command) {
                        return Err(HoldoutError::new(format!(
                            "injected git {failed_command} status=17 stderr=not-evidence"
                        )));
                    }
                    match arguments.first().copied() {
                        Some("status") => Ok(b" M tracked-source\n".to_vec()),
                        Some("diff") => Ok(patch.to_vec()),
                        Some("ls-files") => Ok(Vec::new()),
                        other => panic!("unexpected injected Git command {other:?}"),
                    }
                })
                .expect_err("a failed Git snapshot command must abort snapshot construction");
                assert!(error.to_string().contains("not-evidence"));
            }
        }
    }

    #[test]
    fn nonzero_git_exit_is_an_error_not_snapshot_bytes() {
        let workspace = Path::new(env!("CARGO_MANIFEST_DIR"));
        let error = checked_command_output_bytes(
            workspace,
            "git",
            &["fre-holdout-intentionally-invalid-subcommand"],
        )
        .expect_err("nonzero Git exit must fail closed");
        let message = error.to_string();
        assert!(message.contains("failed: status="));
        assert!(message.contains("stderr_sha256="));
    }

    #[cfg(unix)]
    #[test]
    fn non_utf8_untracked_path_content_change_invalidates_dirty_snapshot() {
        use std::os::unix::ffi::OsStrExt as _;

        let raw_path = b"untracked-\xff-query";
        let mut nul_paths = raw_path.to_vec();
        nul_paths.push(0);
        let framed_a = frame_untracked_source(&nul_paths, |relative| {
            assert_eq!(relative.as_os_str().as_bytes(), raw_path);
            Ok(b"dirty patch A".to_vec())
        })
        .expect("frame non-UTF-8 dirty patch A");
        let framed_b = frame_untracked_source(&nul_paths, |relative| {
            assert_eq!(relative.as_os_str().as_bytes(), raw_path);
            Ok(b"dirty patch B".to_vec())
        })
        .expect("frame non-UTF-8 dirty patch B");
        let patch_a = SourceSnapshotDigests {
            tree: "dirty".to_string(),
            status_sha256: "11".repeat(32),
            diff_sha256: "22".repeat(32),
            untracked_sha256: super::super::sha256(&framed_a),
        };
        let patch_b = SourceSnapshotDigests {
            untracked_sha256: super::super::sha256(&framed_b),
            ..patch_a.clone()
        };

        assert_ne!(framed_a, framed_b);
        assert_ne!(patch_a.untracked_sha256, patch_b.untracked_sha256);
        assert!(verify_embedded_source_snapshot(&patch_a, &patch_b).is_err());
    }

    #[test]
    fn bounded_native_and_same_artifact_portable_preserve_full_anchor_context() {
        let target = host_target().expect("supported native host target");
        let haystack = b"prefix-tail-suffix";
        let window = SearchWindow::new(7, 11);
        for (pattern, expected) in [(r"tail\z", None), (r"\Atail", None), (r"(?:)", Some(7))] {
            let compiled = compile(selected_end_request(pattern, target))
                .unwrap_or_else(|error| panic!("compile {pattern:?}: {error}"));
            let portable = compiled.clone();
            let published = publish_selected_end(compiled, selected_end_publication_limits())
                .unwrap_or_else(|error| panic!("publish {pattern:?}: {error}"));
            let input = AotSelectedEndSearchInput {
                source_index: 0,
                case_id: "anchor-context".to_string(),
                family: "anchor".to_string(),
                labels: vec![],
                pattern: pattern.to_string(),
                input_ordinal: 0,
                declared_intent: "anchor context".to_string(),
                window_kind: AotSelectedEndWindowKind::MidscanNonzeroBounded,
                source_haystack_sha256: super::super::sha256(b"tail"),
                haystack: haystack.to_vec(),
                window_start: window.start(),
                window_end: window.end(),
            };
            let portable_end = portable_end(&portable, &input).expect("portable search");
            let native_end = published.search(haystack, window).expect("native search");
            assert_eq!(native_end, portable_end, "same-artifact parity {pattern:?}");
            assert_eq!(portable_end, expected, "full-context result {pattern:?}");
            let oracle = independent_oracle(pattern).expect("independent oracle");
            let (kind, independent_end) = independent_end(&oracle, &input);
            assert_eq!(kind, INDEPENDENT_BOUNDED_ORACLE);
            assert_eq!(independent_end, expected);
        }
    }

    #[test]
    fn strict_gate_rejects_a_retained_native_fault() {
        let authenticated = fixture(TimingPolicy {
            warmup_iterations: 0,
            measured_iterations: 1,
        });
        let mut report = run_aot_selected_end_correctness(&authenticated)
            .expect("run fixture native AOT correctness");
        report
            .coverage
            .by_input_status
            .insert(AotSelectedEndComparisonStatus::Fault, 1);
        assert!(enforce_aot_selected_end_strict_gate(&report).is_err());
    }

    #[allow(
        clippy::too_many_lines,
        reason = "the retention test constructs and checks every disposition in one closed fixture"
    )]
    #[test]
    fn per_case_declines_and_faults_are_retained_for_every_window() {
        let authenticated = fixture(TimingPolicy {
            warmup_iterations: 0,
            measured_iterations: 1,
        });
        let input = &aot_search_inputs(&authenticated).expect("window inputs")[0];
        let mut case = AotSelectedEndCaseReceipt {
            case_id: input.case_id.clone(),
            family: input.family.clone(),
            labels: input.labels.clone(),
            pattern_sha256: super::super::sha256(input.pattern.as_bytes()),
            input_count: 2,
            search_window_count: 4,
            disposition: AotSelectedEndDisposition::Declined,
            terminal_stage: "compile".to_string(),
            reason_code: Some("compile.decline.resource".to_string()),
            reason: Some("resource ceiling".to_string()),
            compiler: None,
            publication: None,
        };
        let oracle = independent_oracle(&input.pattern).expect("fixture independent oracle");
        let (independent_oracle_kind, independent_end) = independent_end(&oracle, input);
        let declined = compare_input(
            input,
            independent_oracle_kind,
            independent_end,
            &case,
            None,
            None,
        );
        assert_eq!(declined.status, AotSelectedEndComparisonStatus::Declined);
        assert!(!declined.portable_call_attempted);
        assert!(!declined.native_call_attempted);
        assert_eq!(declined.reason_code, case.reason_code);

        case.disposition = AotSelectedEndDisposition::Fault;
        case.reason_code = Some("compile.fault.allocation".to_string());
        case.reason = Some("allocation failure".to_string());
        let fault = compare_input(
            input,
            independent_oracle_kind,
            independent_end,
            &case,
            None,
            None,
        );
        assert_eq!(fault.status, AotSelectedEndComparisonStatus::Fault);
        assert!(!fault.portable_call_attempted);
        assert!(!fault.native_call_attempted);
        assert_eq!(fault.reason_code, case.reason_code);

        let mut declined_report = run_aot_selected_end_correctness(&authenticated)
            .expect("ready fixture before synthetic per-case decline");
        let declined_case = &mut declined_report.cases[0];
        declined_case.disposition = AotSelectedEndDisposition::Declined;
        declined_case.terminal_stage = "compile".to_string();
        declined_case.reason_code = Some("compile.decline.synthetic-resource".to_string());
        declined_case.reason = Some("synthetic resource ceiling".to_string());
        declined_case.compiler = None;
        declined_case.publication = None;
        for receipt in &mut declined_report.comparisons {
            receipt.expected_end = None;
            receipt.actual_end = None;
            receipt.portable_call_attempted = false;
            receipt.native_call_attempted = false;
            receipt.status = AotSelectedEndComparisonStatus::Declined;
            receipt.reason_code = declined_case.reason_code.clone();
            receipt.reason = declined_case.reason.clone();
        }
        declined_report.coverage =
            aot_coverage(&declined_report.cases, &declined_report.comparisons);
        declined_report.receipts_sha256 = super::super::sha256(
            &serde_json::to_vec(&(
                &declined_report.limit_policy,
                &declined_report.cases,
                &declined_report.comparisons,
            ))
            .expect("serialize synthetic decline receipts"),
        );
        validate_aot_selected_end_correctness(&authenticated, &declined_report)
            .expect("synthetic per-case decline remains structurally valid");
        enforce_aot_selected_end_strict_gate(&declined_report)
            .expect("resource decline does not trip strict gate");

        let mut fault_report = declined_report;
        let fault_case = &mut fault_report.cases[0];
        fault_case.disposition = AotSelectedEndDisposition::Fault;
        fault_case.reason_code = Some("compile.fault.synthetic-allocation".to_string());
        fault_case.reason = Some("synthetic allocation fault".to_string());
        for receipt in &mut fault_report.comparisons {
            receipt.status = AotSelectedEndComparisonStatus::Fault;
            receipt.reason_code = fault_case.reason_code.clone();
            receipt.reason = fault_case.reason.clone();
        }
        fault_report.coverage = aot_coverage(&fault_report.cases, &fault_report.comparisons);
        fault_report.receipts_sha256 = super::super::sha256(
            &serde_json::to_vec(&(
                &fault_report.limit_policy,
                &fault_report.cases,
                &fault_report.comparisons,
            ))
            .expect("serialize synthetic fault receipts"),
        );
        validate_aot_selected_end_correctness(&authenticated, &fault_report)
            .expect("synthetic per-case fault remains structurally valid");
        assert!(enforce_aot_selected_end_strict_gate(&fault_report).is_err());
    }

    #[test]
    fn host_faults_are_not_rewritten_as_timing_declines() {
        let authenticated = fixture(TimingPolicy {
            warmup_iterations: 0,
            measured_iterations: 1,
        });
        let host = AotSelectedEndHostReceipt {
            disposition: AotSelectedEndDisposition::Fault,
            target: None,
            reason_code: Some("host-target.fault.synthetic".to_string()),
            reason: Some("synthetic host fault".to_string()),
        };
        let cold = cold_unavailable(&host);
        assert_eq!(cold.terminal, AotSelectedEndTimingTerminal::Fault);
        assert_eq!(cold.reason_code, host.reason_code);
        let setup_receipt = hot_setup_from_host(&authenticated.manifest.cases[0], &host);
        assert_eq!(setup_receipt.terminal, AotSelectedEndTimingTerminal::Fault);
        assert_eq!(setup_receipt.reason_code, host.reason_code);
    }

    #[test]
    fn allocation_and_post_host_invariants_are_faults_but_limits_remain_declines() {
        let allocation = CompileError::Lower(fre_lower::LowerError::AllocationFailed {
            structure: "test",
            additional: 1,
        });
        assert_eq!(
            compile_error_disposition(&allocation),
            AotSelectedEndDisposition::Fault
        );
        assert!(compile_error_code(&allocation).contains("fault"));
        let object_allocation = CompileError::Object(ObjectError::Allocation("test"));
        assert_eq!(
            compile_error_disposition(&object_allocation),
            AotSelectedEndDisposition::Fault
        );
        let object_limit = CompileError::Object(ObjectError::Resource {
            resource: CompileResource::ObjectBytes,
            limit: 1,
            required: 2,
        });
        assert_eq!(
            compile_error_disposition(&object_limit),
            AotSelectedEndDisposition::Declined
        );
        let publication_allocation = PublicationError::AllocationFailed { at: "test" };
        assert_eq!(
            publication_error_disposition(&publication_allocation),
            AotSelectedEndDisposition::Fault
        );
        let publication_limit = PublicationError::Resource {
            resource: fre_aot_regex_loader::PublicationResource::CodeBytes,
            needed: 2,
            limit: 1,
        };
        assert_eq!(
            publication_error_disposition(&publication_limit),
            AotSelectedEndDisposition::Declined
        );
        let jit_denied = PublicationError::JitDenied {
            stage: fre_aot_regex_loader::PublicationStage::ProtectText,
            errno: 1,
        };
        assert_eq!(
            publication_error_disposition(&jit_denied),
            AotSelectedEndDisposition::Declined
        );
    }

    #[test]
    fn authenticated_schedule_is_deterministic_permutation_and_counterbalanced() {
        let authenticated = fixture(TimingPolicy {
            warmup_iterations: 2,
            measured_iterations: 3,
        });
        let correctness = run_aot_selected_end_correctness(&authenticated)
            .expect("fixture correctness for schedule");
        let inputs = aot_search_inputs(&authenticated).expect("schedule window inputs");
        let first = build_timing_schedule(
            &authenticated,
            &correctness.receipts_sha256,
            &correctness.provenance_sha256,
            &correctness.window_matrix_sha256,
            &inputs,
            authenticated.manifest.timing,
        )
        .expect("first schedule");
        let second = build_timing_schedule(
            &authenticated,
            &correctness.receipts_sha256,
            &correctness.provenance_sha256,
            &correctness.window_matrix_sha256,
            &inputs,
            authenticated.manifest.timing,
        )
        .expect("second schedule");
        assert_eq!(first, second);
        for sweeps in [
            &first.cold_warmup,
            &first.cold_measured,
            &first.published_hot_warmup,
            &first.published_hot_measured,
        ] {
            for sweep in sweeps {
                let mut indices = sweep
                    .entries
                    .iter()
                    .map(|entry| entry.input_index)
                    .collect::<Vec<_>>();
                indices.sort_unstable();
                assert_eq!(indices, (0..inputs.len()).collect::<Vec<_>>());
            }
            for pair in sweeps.chunks_exact(2) {
                let forward = pair[0]
                    .entries
                    .iter()
                    .map(|entry| entry.input_index)
                    .collect::<Vec<_>>();
                let reverse = pair[1]
                    .entries
                    .iter()
                    .rev()
                    .map(|entry| entry.input_index)
                    .collect::<Vec<_>>();
                assert_eq!(forward, reverse);
                for first_entry in &pair[0].entries {
                    let second_entry = pair[1]
                        .entries
                        .iter()
                        .find(|entry| entry.input_index == first_entry.input_index)
                        .expect("same input in paired sweep");
                    assert_ne!(first_entry.first_engine, second_entry.first_engine);
                }
            }
        }
    }

    #[test]
    fn correctness_validator_rejects_coverage_and_digest_tampering() {
        let authenticated = fixture(TimingPolicy {
            warmup_iterations: 0,
            measured_iterations: 1,
        });
        let report = run_aot_selected_end_correctness(&authenticated)
            .expect("fixture correctness for tamper test");
        let mut coverage_tamper = report.clone();
        coverage_tamper.coverage.search_windows += 1;
        assert!(validate_aot_selected_end_correctness(&authenticated, &coverage_tamper).is_err());
        let mut limit_tamper = report.clone();
        limit_tamper.limit_policy.compile.max_object_bytes += 1;
        assert!(validate_aot_selected_end_correctness(&authenticated, &limit_tamper).is_err());
        let mut digest_tamper = report;
        let replacement = if digest_tamper.receipts_sha256.starts_with('0') {
            "1"
        } else {
            "0"
        };
        digest_tamper
            .receipts_sha256
            .replace_range(0..1, replacement);
        assert!(validate_aot_selected_end_correctness(&authenticated, &digest_tamper).is_err());
    }
}
