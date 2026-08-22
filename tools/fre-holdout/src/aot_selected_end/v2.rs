//! Default-off V2 policy comparison for the frozen native `SelectedEnd`
//! holdout.
//!
//! Eligibility is frozen by the forced compiler's authenticated supplemental
//! receipt before any timing clock is read. A requested forced policy whose
//! supplemental receipt has no forced route remains explicitly ineligible;
//! its incumbent artifact is never described as the forced candidate.

use std::{
    collections::{BTreeMap, BTreeSet},
    hint::black_box,
    panic::{AssertUnwindSafe, catch_unwind},
    path::PathBuf,
    time::Instant,
};

use fre_aot_regex::{
    COMPILE_REQUEST_V2_SCHEMA_VERSION, CompileRequestV2, CompiledRegexV2,
    EXPERIMENTAL_OPTIMIZER_VERSION_V2, ExactFiniteSelectedEndTeddyIncumbentSourceV2,
    ExactFiniteSelectedEndTeddyPolicyV2, ExactFiniteSelectedEndTeddySelectionBasisV2,
    OutputContract, SearchWindow, Target, compile_v2,
};
use fre_aot_regex_loader::{PublishedSelectedEnd, publish_selected_end};
use serde::{Deserialize, Serialize};

use super::{
    AotSelectedEndCaseReceipt, AotSelectedEndComparisonReceipt, AotSelectedEndComparisonStatus,
    AotSelectedEndCompilerEvidence, AotSelectedEndDisposition, AotSelectedEndHostReceipt,
    AotSelectedEndLimitPolicyReceipt, AotSelectedEndProvenanceReceipt,
    AotSelectedEndPublicationEvidence, AotSelectedEndSearchInput, AotSelectedEndWindowKind,
    aot_search_inputs, aot_window_matrix_sha256, call_error_code, collect_provenance,
    compare_input, compile_error_code, compile_error_disposition, compiler_evidence,
    independent_end, independent_oracle, publication_error_code, publication_error_disposition,
    publication_evidence, resolve_host_target, selected_end_limit_policy,
    selected_end_publication_limits, selected_end_request, target_from_receipt,
    verified_performance_target,
};
use crate::{AuthenticatedSuite, CaseSpec, HoldoutError, TimingPolicy, authenticate_paths};

/// Clock-free schema for the explicit V2 policy comparison.
pub const AOT_SELECTED_END_V2_CORRECTNESS_SCHEMA: &str =
    "fre.holdout.aot-selected-end-v2-comparison.correctness.v2";
/// Non-normative hot timing schema for the explicit V2 policy comparison.
pub const AOT_SELECTED_END_V2_PERFORMANCE_SCHEMA: &str =
    "fre.holdout.aot-selected-end-v2-comparison.performance.v2";
const V2_POLICY_ARTIFACT_BINDING_SCHEMA: &str =
    "fre.holdout.aot-selected-end-v2-comparison.artifact-binding.v2";
const V2_ELIGIBILITY_SCHEMA: &str = "fre.holdout.aot-selected-end-v2-comparison.eligibility.v2";
const V2_SCHEDULE_SCHEMA: &str = "fre.holdout.aot-selected-end-v2-comparison.schedule.v1";
const V2_OBSERVATION_BUDGET_SCHEMA: &str =
    "fre.holdout.aot-selected-end-v2-comparison.observation-budget.v1";
const V2_CORRECTNESS_CANDIDATE_IDENTITY: &str = "two separately compiled fre-aot-regex CompileRequestV2 optimizing OutputContract::SelectedEnd artifacts: explicit Automatic and explicit ForceStructurallyEligible; each is published independently by fre-aot-regex-loader under strict W^X and invoked only through its native entry; a missing forced supplemental route remains an incumbent fallback and is never labeled forced";
const V2_CORRECTNESS_ORACLE_IDENTITY: &str = "for each policy artifact and every authenticated full/nonzero-bounded window: mandatory same-artifact CompiledRegex::search SelectedEnd plus independent regex::bytes 1.12.4 full-window or regex-automata 0.4.15 Input::span bounded-window oracle";
const V2_ELIGIBILITY_IDENTITY: &str = "case eligibility is frozen before timing iff the ForceStructurallyEligible CompileRequestV2 supplemental receipt contains an authenticated ForcedStructuralEligibility report; no elapsed duration, Automatic receipt, publication result, or search result participates";
const V2_HOT_MEASUREMENT_SCOPE: &str = "one independently published Automatic matcher and one independently published ForceStructurallyEligible matcher per frozen-eligible case are constructed before hot sweeps; compile and publish durations are separate setup fields; each hot sample clocks exactly one direct native SelectedEnd search on an identical authenticated window";
const V2_PAIRING_DESCRIPTION: &str = "every warmup and measured sweep is a deterministic authenticated permutation of only the frozen-eligible full/bounded windows; adjacent sweeps use a permutation and its reverse; the first policy alternates per input and repetition while both policies remain adjacent in one paired point";
const MAX_V2_TIMING_OBSERVATIONS: usize = 65_536;

/// Paths for the explicit, default-off V2 experiment.
#[derive(Clone, Debug)]
pub struct AotSelectedEndV2RunConfig {
    pub suite: PathBuf,
    pub schema: PathBuf,
    pub digests: PathBuf,
    pub correctness_output: PathBuf,
    pub performance_output: Option<PathBuf>,
}

/// Compiler policy requested for one independently compiled artifact.
#[derive(Clone, Copy, Debug, Deserialize, Serialize, Eq, Ord, PartialEq, PartialOrd)]
#[serde(rename_all = "kebab-case")]
pub enum AotSelectedEndV2Policy {
    Automatic,
    ForceStructurallyEligible,
}

impl AotSelectedEndV2Policy {
    const ALL: [Self; 2] = [Self::Automatic, Self::ForceStructurallyEligible];

    const fn compiler_policy(self) -> ExactFiniteSelectedEndTeddyPolicyV2 {
        match self {
            Self::Automatic => ExactFiniteSelectedEndTeddyPolicyV2::Automatic,
            Self::ForceStructurallyEligible => {
                ExactFiniteSelectedEndTeddyPolicyV2::ForceStructurallyEligible
            }
        }
    }
}

/// Structural eligibility outcome retained for every frozen case.
#[derive(Clone, Copy, Debug, Deserialize, Serialize, Eq, Ord, PartialEq, PartialOrd)]
#[serde(rename_all = "kebab-case")]
pub enum AotSelectedEndV2Eligibility {
    StructurallyEligible,
    StructurallyIneligible,
    CompileDeclined,
    Fault,
}

/// Authenticated route details copied from a selected V2 supplemental report.
#[derive(Clone, Debug, Deserialize, Serialize, Eq, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct AotSelectedEndV2RouteEvidence {
    pub report_schema_version: u32,
    pub requested_policy: AotSelectedEndV2Policy,
    pub selection_basis: String,
    pub incumbent_source: String,
    pub incumbent_start_accelerator: String,
    pub incumbent_anchored_prefix_filter_bytes: u8,
    pub performance_admission_bypassed: bool,
    pub tail_enters_exact_incumbent: bool,
    pub route_binding_sha256: String,
    pub program_artifact_identity_sha256: String,
    pub report_artifact_identity_sha256: String,
    pub prefix_plan_sha256: String,
    pub native_code_sha256: String,
    pub native_data_sha256: String,
    pub relocations_sha256: String,
    pub incumbent_code_sha256: String,
    pub incumbent_data_sha256: String,
    pub incumbent_relocations_sha256: String,
    pub semantic_dfa_sha256: String,
    pub selected_target_tier: String,
    pub emitted_isa: String,
    pub target: String,
    pub source_count: u32,
    pub source_bytes: usize,
    pub minimum_width: u32,
    pub maximum_width: u32,
    pub batch_vectors: u8,
    pub runtime_verification_budget: u16,
}

/// Supplemental V2 receipt and its stable/module leakage checks.
#[derive(Clone, Debug, Deserialize, Serialize, Eq, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct AotSelectedEndV2SupplementalEvidence {
    pub request_schema_version: u32,
    pub experimental_optimizer_version: u32,
    pub requested_policy: AotSelectedEndV2Policy,
    pub stable_optimizer_version: u32,
    pub stable_v1_teddy_report_present: bool,
    pub module_v1_teddy_report_present: bool,
    pub module_v2_teddy_report_present: bool,
    pub route: Option<AotSelectedEndV2RouteEvidence>,
}

impl AotSelectedEndV2SupplementalEvidence {
    const fn route_selected(&self) -> bool {
        self.route.is_some()
    }
}

/// One requested-policy compile/publication result. `route_selected` refers
/// only to the authenticated supplemental route, not to mere compile success.
#[derive(Clone, Debug, Deserialize, Serialize, Eq, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct AotSelectedEndV2PolicyArtifactReceipt {
    pub policy: AotSelectedEndV2Policy,
    pub route_selected: bool,
    pub build: AotSelectedEndCaseReceipt,
    pub supplemental: Option<AotSelectedEndV2SupplementalEvidence>,
    pub artifact_binding_sha256: Option<String>,
}

/// Both policy artifacts and the frozen structural classification for a case.
#[derive(Clone, Debug, Deserialize, Serialize, Eq, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct AotSelectedEndV2CaseReceipt {
    pub case_id: String,
    pub family: String,
    pub labels: Vec<String>,
    pub pattern_sha256: String,
    pub input_count: usize,
    pub search_window_count: usize,
    pub eligibility: AotSelectedEndV2Eligibility,
    pub automatic: AotSelectedEndV2PolicyArtifactReceipt,
    pub force_structurally_eligible: AotSelectedEndV2PolicyArtifactReceipt,
}

impl AotSelectedEndV2CaseReceipt {
    fn artifact(&self, policy: AotSelectedEndV2Policy) -> &AotSelectedEndV2PolicyArtifactReceipt {
        match policy {
            AotSelectedEndV2Policy::Automatic => &self.automatic,
            AotSelectedEndV2Policy::ForceStructurallyEligible => &self.force_structurally_eligible,
        }
    }
}

/// One policy-specific correctness result for an authenticated window.
#[derive(Clone, Debug, Deserialize, Serialize, Eq, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct AotSelectedEndV2ComparisonReceipt {
    pub policy: AotSelectedEndV2Policy,
    pub route_selected: bool,
    pub comparison: AotSelectedEndComparisonReceipt,
}

/// Recomputable coverage, including every ineligible and unavailable case.
#[derive(Clone, Debug, Default, Deserialize, Serialize, Eq, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct AotSelectedEndV2Coverage {
    pub case_patterns: usize,
    pub expanded_inputs: usize,
    pub search_windows_per_policy: usize,
    pub policy_comparisons: usize,
    pub frozen_eligible_cases: usize,
    pub frozen_eligible_search_windows: usize,
    pub by_eligibility: BTreeMap<AotSelectedEndV2Eligibility, usize>,
    pub by_policy_case_disposition:
        BTreeMap<AotSelectedEndV2Policy, BTreeMap<AotSelectedEndDisposition, usize>>,
    pub by_policy_route_selected: BTreeMap<AotSelectedEndV2Policy, usize>,
    pub by_policy_input_status:
        BTreeMap<AotSelectedEndV2Policy, BTreeMap<AotSelectedEndComparisonStatus, usize>>,
    pub by_policy_window_kind_status: BTreeMap<
        AotSelectedEndV2Policy,
        BTreeMap<AotSelectedEndWindowKind, BTreeMap<AotSelectedEndComparisonStatus, usize>>,
    >,
}

/// Clock-free, authenticated policy comparison.
#[derive(Clone, Debug, Deserialize, Serialize, Eq, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct AotSelectedEndV2CorrectnessReport {
    pub schema: String,
    pub suite_id: String,
    pub suite_sha256: String,
    pub json_schema_sha256: String,
    pub expanded_inputs_sha256: String,
    pub window_matrix_sha256: String,
    pub candidate_identity: String,
    pub oracle_identity: String,
    pub eligibility_identity: String,
    pub target_arch: String,
    pub target_os: String,
    pub target_pointer_width: u32,
    pub host: AotSelectedEndHostReceipt,
    pub provenance: AotSelectedEndProvenanceReceipt,
    pub limit_policy: AotSelectedEndLimitPolicyReceipt,
    pub provenance_sha256: String,
    pub eligibility_sha256: String,
    pub receipts_sha256: String,
    pub frozen_eligible_case_ids: Vec<String>,
    pub coverage: AotSelectedEndV2Coverage,
    pub cases: Vec<AotSelectedEndV2CaseReceipt>,
    pub comparisons: Vec<AotSelectedEndV2ComparisonReceipt>,
}

#[derive(Debug)]
struct LiveV2PolicyArtifact {
    receipt: AotSelectedEndV2PolicyArtifactReceipt,
    portable: Option<fre_aot_regex::CompiledRegex>,
    published: Option<PublishedSelectedEnd>,
}

/// Authenticate and execute the default-off V2 comparison, optionally
/// followed by its separate non-normative timing campaign.
pub fn run_aot_selected_end_v2_experiment(
    config: &AotSelectedEndV2RunConfig,
) -> Result<AotSelectedEndV2CorrectnessReport, HoldoutError> {
    let authenticated = authenticate_paths(&config.suite, &config.schema, &config.digests)?;
    let correctness = run_aot_selected_end_v2_correctness(&authenticated)?;
    crate::write_json(&config.correctness_output, &correctness)?;
    if let Some(path) = &config.performance_output {
        let performance = run_aot_selected_end_v2_performance(&authenticated, &correctness)?;
        crate::write_json(path, &performance)?;
    }
    Ok(correctness)
}

/// Compile both explicit V2 policies and compare both artifacts on every full
/// and bounded authenticated window without consulting a clock.
#[allow(
    clippy::too_many_lines,
    reason = "the frozen two-policy matrix, eligibility freeze, and receipt digests are one auditable clock-free transaction"
)]
pub fn run_aot_selected_end_v2_correctness(
    authenticated: &AuthenticatedSuite,
) -> Result<AotSelectedEndV2CorrectnessReport, HoldoutError> {
    let provenance = collect_provenance()?;
    let (host, target) = resolve_host_target();
    let search_inputs = aot_search_inputs(authenticated)?;
    let window_matrix_sha256 = aot_window_matrix_sha256(authenticated, &search_inputs)?;
    let mut cases = Vec::new();
    let mut comparisons = Vec::new();

    for case in &authenticated.manifest.cases {
        let oracle = independent_oracle(&case.pattern).map_err(|error| {
            HoldoutError::new(format!(
                "case {} V2 independent oracle construction: {error}",
                case.id
            ))
        })?;
        let input_count = authenticated
            .inputs
            .iter()
            .filter(|input| input.case_id == case.id)
            .count();
        let inputs = search_inputs
            .iter()
            .filter(|input| input.case_id == case.id)
            .collect::<Vec<_>>();
        let automatic = build_v2_policy_artifact(
            case,
            input_count,
            inputs.len(),
            AotSelectedEndV2Policy::Automatic,
            target,
            &host,
        );
        let forced = build_v2_policy_artifact(
            case,
            input_count,
            inputs.len(),
            AotSelectedEndV2Policy::ForceStructurallyEligible,
            target,
            &host,
        );
        let eligibility = forced_eligibility(&forced.receipt);

        for &input in &inputs {
            let (oracle_kind, oracle_end) = independent_end(&oracle, input);
            for (policy, built) in [
                (AotSelectedEndV2Policy::Automatic, &automatic),
                (AotSelectedEndV2Policy::ForceStructurallyEligible, &forced),
            ] {
                comparisons.push(AotSelectedEndV2ComparisonReceipt {
                    policy,
                    route_selected: built.receipt.route_selected,
                    comparison: compare_input(
                        input,
                        oracle_kind,
                        oracle_end,
                        &built.receipt.build,
                        built.portable.as_ref(),
                        built.published.as_ref(),
                    ),
                });
            }
        }
        cases.push(AotSelectedEndV2CaseReceipt {
            case_id: case.id.clone(),
            family: case.family.clone(),
            labels: case.labels.clone(),
            pattern_sha256: crate::sha256(case.pattern.as_bytes()),
            input_count,
            search_window_count: inputs.len(),
            eligibility,
            automatic: automatic.receipt,
            force_structurally_eligible: forced.receipt,
        });
    }

    let expected_comparisons = search_inputs
        .len()
        .checked_mul(AotSelectedEndV2Policy::ALL.len())
        .ok_or_else(|| HoldoutError::new("V2 correctness matrix length overflow"))?;
    if cases.len() != authenticated.manifest.cases.len()
        || comparisons.len() != expected_comparisons
    {
        return Err(HoldoutError::new(format!(
            "V2 correctness generated {} cases and {} policy windows, expected {} and {}",
            cases.len(),
            comparisons.len(),
            authenticated.manifest.cases.len(),
            expected_comparisons
        )));
    }
    let frozen_eligible_case_ids = cases
        .iter()
        .filter(|case| case.eligibility == AotSelectedEndV2Eligibility::StructurallyEligible)
        .map(|case| case.case_id.clone())
        .collect::<Vec<_>>();
    let limit_policy = selected_end_limit_policy();
    let eligibility_sha256 = eligibility_sha256(
        authenticated,
        &window_matrix_sha256,
        &host,
        &limit_policy,
        &cases,
        &frozen_eligible_case_ids,
    )?;
    let coverage = v2_coverage(authenticated.inputs.len(), &cases, &comparisons);
    let provenance_bytes = serde_json::to_vec(&(&host, &provenance))
        .map_err(|error| HoldoutError::new(format!("serialize V2 provenance: {error}")))?;
    let receipt_bytes = serde_json::to_vec(&(
        &limit_policy,
        &eligibility_sha256,
        &frozen_eligible_case_ids,
        &cases,
        &comparisons,
    ))
    .map_err(|error| HoldoutError::new(format!("serialize V2 correctness receipts: {error}")))?;
    let report = AotSelectedEndV2CorrectnessReport {
        schema: AOT_SELECTED_END_V2_CORRECTNESS_SCHEMA.to_string(),
        suite_id: authenticated.manifest.suite_id.clone(),
        suite_sha256: authenticated.suite_sha256.clone(),
        json_schema_sha256: authenticated.json_schema_sha256.clone(),
        expanded_inputs_sha256: authenticated.expanded_inputs_sha256.clone(),
        window_matrix_sha256,
        candidate_identity: V2_CORRECTNESS_CANDIDATE_IDENTITY.to_string(),
        oracle_identity: V2_CORRECTNESS_ORACLE_IDENTITY.to_string(),
        eligibility_identity: V2_ELIGIBILITY_IDENTITY.to_string(),
        target_arch: std::env::consts::ARCH.to_string(),
        target_os: std::env::consts::OS.to_string(),
        target_pointer_width: usize::BITS,
        host,
        provenance,
        limit_policy,
        provenance_sha256: crate::sha256(&provenance_bytes),
        eligibility_sha256,
        receipts_sha256: crate::sha256(&receipt_bytes),
        frozen_eligible_case_ids,
        coverage,
        cases,
        comparisons,
    };
    validate_aot_selected_end_v2_correctness(authenticated, &report)?;
    Ok(report)
}

fn v2_request(case: &CaseSpec, target: Target, policy: AotSelectedEndV2Policy) -> CompileRequestV2 {
    CompileRequestV2::new(selected_end_request(&case.pattern, target))
        .exact_finite_selected_end_teddy(policy.compiler_policy())
}

fn build_v2_policy_artifact(
    case: &CaseSpec,
    input_count: usize,
    search_window_count: usize,
    policy: AotSelectedEndV2Policy,
    target: Option<Target>,
    host: &AotSelectedEndHostReceipt,
) -> LiveV2PolicyArtifact {
    let Some(target) = target else {
        return unavailable_v2_policy_artifact(
            case,
            input_count,
            search_window_count,
            policy,
            host,
        );
    };
    let compiled = match catch_unwind(AssertUnwindSafe(|| {
        compile_v2(v2_request(case, target, policy))
    })) {
        Err(_) => {
            return failed_v2_policy_artifact(
                case,
                input_count,
                search_window_count,
                policy,
                AotSelectedEndDisposition::Fault,
                "compile",
                "compile-v2.panic",
                "CompileRequestV2 compiler panicked".to_string(),
                None,
                None,
            );
        }
        Ok(Err(error)) => {
            return failed_v2_policy_artifact(
                case,
                input_count,
                search_window_count,
                policy,
                compile_error_disposition(&error),
                "compile",
                &compile_error_code(&error).replace("compile.", "compile-v2."),
                error.to_string(),
                None,
                None,
            );
        }
        Ok(Ok(compiled)) => compiled,
    };
    finish_v2_policy_artifact(case, input_count, search_window_count, policy, compiled)
}

#[allow(
    clippy::too_many_lines,
    reason = "compilation evidence, supplemental policy closure, publication, and artifact binding form one transaction"
)]
fn finish_v2_policy_artifact(
    case: &CaseSpec,
    input_count: usize,
    search_window_count: usize,
    policy: AotSelectedEndV2Policy,
    compiled: CompiledRegexV2,
) -> LiveV2PolicyArtifact {
    let compiler_receipt = compiler_evidence(compiled.compiled());
    let supplemental = match v2_supplemental_evidence(&compiled, policy) {
        Ok(evidence) => evidence,
        Err(error) => {
            return failed_v2_policy_artifact(
                case,
                input_count,
                search_window_count,
                policy,
                AotSelectedEndDisposition::Fault,
                "compile-receipt-v2",
                "compile-v2.fault.policy-receipt-closure",
                error.to_string(),
                Some(compiler_receipt),
                None,
            );
        }
    };
    let route_selected = supplemental.route_selected();
    let portable = compiled.compiled().clone();
    let published = match catch_unwind(AssertUnwindSafe(|| {
        publish_selected_end(compiled.into_compiled(), selected_end_publication_limits())
    })) {
        Err(_) => {
            return failed_v2_policy_artifact(
                case,
                input_count,
                search_window_count,
                policy,
                AotSelectedEndDisposition::Fault,
                "publish",
                "publish-v2.panic",
                "V2 in-memory SelectedEnd publication panicked".to_string(),
                Some(compiler_receipt),
                Some(supplemental),
            );
        }
        Ok(Err(error)) => {
            return failed_v2_policy_artifact(
                case,
                input_count,
                search_window_count,
                policy,
                publication_error_disposition(&error),
                "publish",
                &publication_error_code(&error, "publish-v2"),
                error.to_string(),
                Some(compiler_receipt),
                Some(supplemental),
            );
        }
        Ok(Ok(published)) => published,
    };
    let publication = publication_evidence(&published);
    if compiler_receipt.object_sha256 != publication.identity_sha256 {
        return failed_v2_policy_artifact(
            case,
            input_count,
            search_window_count,
            policy,
            AotSelectedEndDisposition::Fault,
            "publish-identity",
            "publish-v2.fault.object-identity",
            "V2 compiler object identity differs from published mapping identity".to_string(),
            Some(compiler_receipt),
            Some(supplemental),
        );
    }
    let artifact_binding_sha256 =
        match v2_artifact_binding_sha256(policy, &compiler_receipt, &supplemental, &publication) {
            Ok(binding) => binding,
            Err(error) => {
                return failed_v2_policy_artifact(
                    case,
                    input_count,
                    search_window_count,
                    policy,
                    AotSelectedEndDisposition::Fault,
                    "publish-identity",
                    "publish-v2.fault.binding",
                    error.to_string(),
                    Some(compiler_receipt),
                    Some(supplemental),
                );
            }
        };
    LiveV2PolicyArtifact {
        receipt: AotSelectedEndV2PolicyArtifactReceipt {
            policy,
            route_selected,
            build: base_case_receipt(
                case,
                input_count,
                search_window_count,
                AotSelectedEndDisposition::Ready,
                "ready",
                None,
                None,
                Some(compiler_receipt),
                Some(publication),
            ),
            supplemental: Some(supplemental),
            artifact_binding_sha256: Some(artifact_binding_sha256),
        },
        portable: Some(portable),
        published: Some(published),
    }
}

#[allow(
    clippy::too_many_arguments,
    reason = "the failure constructor retains policy, authenticated dimensions, terminal classification, and partial evidence"
)]
fn failed_v2_policy_artifact(
    case: &CaseSpec,
    input_count: usize,
    search_window_count: usize,
    policy: AotSelectedEndV2Policy,
    disposition: AotSelectedEndDisposition,
    terminal_stage: &str,
    reason_code: &str,
    reason: String,
    compiler: Option<AotSelectedEndCompilerEvidence>,
    supplemental: Option<AotSelectedEndV2SupplementalEvidence>,
) -> LiveV2PolicyArtifact {
    let route_selected = supplemental
        .as_ref()
        .is_some_and(AotSelectedEndV2SupplementalEvidence::route_selected);
    LiveV2PolicyArtifact {
        receipt: AotSelectedEndV2PolicyArtifactReceipt {
            policy,
            route_selected,
            build: base_case_receipt(
                case,
                input_count,
                search_window_count,
                disposition,
                terminal_stage,
                Some(reason_code.to_string()),
                Some(reason),
                compiler,
                None,
            ),
            supplemental,
            artifact_binding_sha256: None,
        },
        portable: None,
        published: None,
    }
}

fn unavailable_v2_policy_artifact(
    case: &CaseSpec,
    input_count: usize,
    search_window_count: usize,
    policy: AotSelectedEndV2Policy,
    host: &AotSelectedEndHostReceipt,
) -> LiveV2PolicyArtifact {
    LiveV2PolicyArtifact {
        receipt: AotSelectedEndV2PolicyArtifactReceipt {
            policy,
            route_selected: false,
            build: base_case_receipt(
                case,
                input_count,
                search_window_count,
                host.disposition,
                "host-target",
                host.reason_code.clone(),
                host.reason.clone(),
                None,
                None,
            ),
            supplemental: None,
            artifact_binding_sha256: None,
        },
        portable: None,
        published: None,
    }
}

#[allow(
    clippy::too_many_arguments,
    reason = "the base receipt shape keeps every terminal closure field explicit"
)]
fn base_case_receipt(
    case: &CaseSpec,
    input_count: usize,
    search_window_count: usize,
    disposition: AotSelectedEndDisposition,
    terminal_stage: &str,
    reason_code: Option<String>,
    reason: Option<String>,
    compiler: Option<AotSelectedEndCompilerEvidence>,
    publication: Option<AotSelectedEndPublicationEvidence>,
) -> AotSelectedEndCaseReceipt {
    AotSelectedEndCaseReceipt {
        case_id: case.id.clone(),
        family: case.family.clone(),
        labels: case.labels.clone(),
        pattern_sha256: crate::sha256(case.pattern.as_bytes()),
        input_count,
        search_window_count,
        disposition,
        terminal_stage: terminal_stage.to_string(),
        reason_code,
        reason,
        compiler,
        publication,
    }
}

#[allow(
    clippy::too_many_lines,
    reason = "schema, policy, leakage, module, structural route, and artifact evidence are closed together"
)]
fn v2_supplemental_evidence(
    compiled: &CompiledRegexV2,
    policy: AotSelectedEndV2Policy,
) -> Result<AotSelectedEndV2SupplementalEvidence, HoldoutError> {
    let stable = compiled.compiled().receipt();
    let supplemental = compiled.receipt_v2();
    let module_v1 = compiled
        .compiled()
        .module()
        .exact_finite_selected_end_teddy_aot_report();
    let module_v2 = compiled
        .compiled()
        .module()
        .exact_finite_selected_end_teddy_aot_report_v2();
    if supplemental.schema_version != COMPILE_REQUEST_V2_SCHEMA_VERSION
        || supplemental.optimizer_version != EXPERIMENTAL_OPTIMIZER_VERSION_V2
        || supplemental.exact_finite_selected_end_teddy_policy != policy.compiler_policy()
    {
        return Err(HoldoutError::new(
            "CompileRequestV2 supplemental schema/optimizer/policy binding is invalid",
        ));
    }
    match policy {
        AotSelectedEndV2Policy::Automatic => {
            if module_v2.is_some()
                || module_v1 != stable.exact_finite_selected_end_teddy_aot.as_ref()
                || supplemental
                    .exact_finite_selected_end_teddy_aot
                    .as_ref()
                    .map(|report| &report.lowering)
                    != stable.exact_finite_selected_end_teddy_aot.as_ref()
            {
                return Err(HoldoutError::new(
                    "Automatic V2 supplemental/stable/module receipt closure is invalid",
                ));
            }
        }
        AotSelectedEndV2Policy::ForceStructurallyEligible => {
            if stable.exact_finite_selected_end_teddy_aot.is_some()
                || module_v1.is_some()
                || module_v2 != supplemental.exact_finite_selected_end_teddy_aot.as_ref()
            {
                return Err(HoldoutError::new(
                    "forced V2 evidence leaked into V1 or disagrees with the module receipt",
                ));
            }
        }
    }
    let route = supplemental
        .exact_finite_selected_end_teddy_aot
        .as_ref()
        .map(|report| {
            let expected_basis = match policy {
                AotSelectedEndV2Policy::Automatic => {
                    ExactFiniteSelectedEndTeddySelectionBasisV2::AutomaticV1
                }
                AotSelectedEndV2Policy::ForceStructurallyEligible => {
                    ExactFiniteSelectedEndTeddySelectionBasisV2::ForcedStructuralEligibility
                }
            };
            if report.schema_version != COMPILE_REQUEST_V2_SCHEMA_VERSION
                || report.requested_policy != policy.compiler_policy()
                || report.selection_basis != expected_basis
                || report.incumbent_source
                    != ExactFiniteSelectedEndTeddyIncumbentSourceV2::OrdinaryPublicCompleteDfa
                || report.performance_admission_bypassed
                    != (policy == AotSelectedEndV2Policy::ForceStructurallyEligible)
                || !report.tail_enters_exact_incumbent
                || report.lowering.output != OutputContract::SelectedEnd
                || report.lowering.target != stable.target
                || report.lowering.artifact_identity
                    != compiled.compiled().program().artifact_identity()
                || report.route_binding_sha256 == [0; 32]
            {
                return Err(HoldoutError::new(
                    "selected V2 route has invalid structural provenance",
                ));
            }
            Ok(AotSelectedEndV2RouteEvidence {
                report_schema_version: report.schema_version,
                requested_policy: policy,
                selection_basis: format!("{:?}", report.selection_basis),
                incumbent_source: format!("{:?}", report.incumbent_source),
                incumbent_start_accelerator: format!("{:?}", report.incumbent_start_accelerator),
                incumbent_anchored_prefix_filter_bytes: report
                    .incumbent_anchored_prefix_filter_bytes,
                performance_admission_bypassed: report.performance_admission_bypassed,
                tail_enters_exact_incumbent: report.tail_enters_exact_incumbent,
                route_binding_sha256: super::hex_bytes(&report.route_binding_sha256),
                program_artifact_identity_sha256: super::hex_bytes(
                    &compiled.compiled().program().artifact_identity(),
                ),
                report_artifact_identity_sha256: super::hex_bytes(
                    &report.lowering.artifact_identity,
                ),
                prefix_plan_sha256: super::hex_bytes(&report.lowering.prefix_plan_sha256),
                native_code_sha256: super::hex_bytes(&report.lowering.native_code_sha256),
                native_data_sha256: super::hex_bytes(&report.lowering.native_data_sha256),
                relocations_sha256: super::hex_bytes(&report.lowering.relocations_sha256),
                incumbent_code_sha256: super::hex_bytes(&report.lowering.incumbent_code_sha256),
                incumbent_data_sha256: super::hex_bytes(&report.lowering.incumbent_data_sha256),
                incumbent_relocations_sha256: super::hex_bytes(
                    &report.lowering.incumbent_relocations_sha256,
                ),
                semantic_dfa_sha256: super::hex_bytes(
                    &report.lowering.incumbent_complete_dfa.semantic_dfa_sha256,
                ),
                selected_target_tier: format!("{:?}", report.lowering.selected_target_tier),
                emitted_isa: format!("{:?}", report.lowering.emitted_isa),
                target: format!("{:?}", report.lowering.target),
                source_count: report.lowering.source_count,
                source_bytes: report.lowering.source_bytes,
                minimum_width: report.lowering.minimum_width,
                maximum_width: report.lowering.maximum_width,
                batch_vectors: report.lowering.batch_vectors,
                runtime_verification_budget: report.lowering.runtime_verification_budget,
            })
        })
        .transpose()?;
    Ok(AotSelectedEndV2SupplementalEvidence {
        request_schema_version: supplemental.schema_version,
        experimental_optimizer_version: supplemental.optimizer_version,
        requested_policy: policy,
        stable_optimizer_version: stable.optimizer_version,
        stable_v1_teddy_report_present: stable.exact_finite_selected_end_teddy_aot.is_some(),
        module_v1_teddy_report_present: module_v1.is_some(),
        module_v2_teddy_report_present: module_v2.is_some(),
        route,
    })
}

fn v2_artifact_binding_sha256(
    policy: AotSelectedEndV2Policy,
    compiler: &AotSelectedEndCompilerEvidence,
    supplemental: &AotSelectedEndV2SupplementalEvidence,
    publication: &AotSelectedEndPublicationEvidence,
) -> Result<String, HoldoutError> {
    if compiler.object_sha256 != publication.identity_sha256 {
        return Err(HoldoutError::new(
            "cannot bind a V2 artifact whose module and publication identities differ",
        ));
    }
    let bytes = serde_json::to_vec(&(
        V2_POLICY_ARTIFACT_BINDING_SCHEMA,
        policy,
        compiler,
        supplemental,
        publication,
    ))
    .map_err(|error| HoldoutError::new(format!("serialize V2 artifact binding: {error}")))?;
    Ok(crate::sha256(&bytes))
}

fn forced_eligibility(
    forced: &AotSelectedEndV2PolicyArtifactReceipt,
) -> AotSelectedEndV2Eligibility {
    match forced.supplemental.as_ref() {
        Some(supplemental) if supplemental.route.is_some() => {
            AotSelectedEndV2Eligibility::StructurallyEligible
        }
        Some(_) => AotSelectedEndV2Eligibility::StructurallyIneligible,
        None if forced.build.disposition == AotSelectedEndDisposition::Declined => {
            AotSelectedEndV2Eligibility::CompileDeclined
        }
        None => AotSelectedEndV2Eligibility::Fault,
    }
}

fn eligibility_sha256(
    authenticated: &AuthenticatedSuite,
    window_matrix_sha256: &str,
    host: &AotSelectedEndHostReceipt,
    limit_policy: &AotSelectedEndLimitPolicyReceipt,
    cases: &[AotSelectedEndV2CaseReceipt],
    eligible_case_ids: &[String],
) -> Result<String, HoldoutError> {
    let structural = cases
        .iter()
        .map(|case| {
            (
                &case.case_id,
                &case.pattern_sha256,
                case.input_count,
                case.search_window_count,
                case.eligibility,
                case.force_structurally_eligible.policy,
                case.force_structurally_eligible.route_selected,
                &case.force_structurally_eligible.supplemental,
            )
        })
        .collect::<Vec<_>>();
    let bytes = serde_json::to_vec(&(
        V2_ELIGIBILITY_SCHEMA,
        V2_ELIGIBILITY_IDENTITY,
        &authenticated.suite_sha256,
        &authenticated.expanded_inputs_sha256,
        window_matrix_sha256,
        host,
        limit_policy,
        structural,
        eligible_case_ids,
    ))
    .map_err(|error| HoldoutError::new(format!("serialize V2 eligibility freeze: {error}")))?;
    Ok(crate::sha256(&bytes))
}

fn v2_coverage(
    expanded_inputs: usize,
    cases: &[AotSelectedEndV2CaseReceipt],
    comparisons: &[AotSelectedEndV2ComparisonReceipt],
) -> AotSelectedEndV2Coverage {
    let mut coverage = AotSelectedEndV2Coverage {
        case_patterns: cases.len(),
        expanded_inputs,
        search_windows_per_policy: comparisons
            .len()
            .checked_div(AotSelectedEndV2Policy::ALL.len())
            .expect("the V2 policy list is nonempty"),
        policy_comparisons: comparisons.len(),
        ..AotSelectedEndV2Coverage::default()
    };
    for case in cases {
        super::increment(coverage.by_eligibility.entry(case.eligibility).or_default());
        if case.eligibility == AotSelectedEndV2Eligibility::StructurallyEligible {
            super::increment(&mut coverage.frozen_eligible_cases);
            coverage.frozen_eligible_search_windows = coverage
                .frozen_eligible_search_windows
                .checked_add(case.search_window_count)
                .expect("authenticated V2 window counts are bounded");
        }
        for policy in AotSelectedEndV2Policy::ALL {
            let artifact = case.artifact(policy);
            super::increment(
                coverage
                    .by_policy_case_disposition
                    .entry(policy)
                    .or_default()
                    .entry(artifact.build.disposition)
                    .or_default(),
            );
            if artifact.route_selected {
                super::increment(coverage.by_policy_route_selected.entry(policy).or_default());
            }
        }
    }
    for receipt in comparisons {
        super::increment(
            coverage
                .by_policy_input_status
                .entry(receipt.policy)
                .or_default()
                .entry(receipt.comparison.status)
                .or_default(),
        );
        super::increment(
            coverage
                .by_policy_window_kind_status
                .entry(receipt.policy)
                .or_default()
                .entry(receipt.comparison.window_kind)
                .or_default()
                .entry(receipt.comparison.status)
                .or_default(),
        );
    }
    coverage
}

/// Reject either policy's semantic failures and implementation faults while
/// retaining resource declines and structurally ineligible cases as coverage.
pub fn enforce_aot_selected_end_v2_strict_gate(
    report: &AotSelectedEndV2CorrectnessReport,
) -> Result<(), HoldoutError> {
    let mut failures = 0_usize;
    let mut input_faults = 0_usize;
    let mut case_faults = 0_usize;
    for policy in AotSelectedEndV2Policy::ALL {
        failures = failures.saturating_add(
            report
                .coverage
                .by_policy_input_status
                .get(&policy)
                .and_then(|statuses| statuses.get(&AotSelectedEndComparisonStatus::Fail))
                .copied()
                .unwrap_or(0),
        );
        input_faults = input_faults.saturating_add(
            report
                .coverage
                .by_policy_input_status
                .get(&policy)
                .and_then(|statuses| statuses.get(&AotSelectedEndComparisonStatus::Fault))
                .copied()
                .unwrap_or(0),
        );
        case_faults = case_faults.saturating_add(
            report
                .coverage
                .by_policy_case_disposition
                .get(&policy)
                .and_then(|statuses| statuses.get(&AotSelectedEndDisposition::Fault))
                .copied()
                .unwrap_or(0),
        );
    }
    if failures == 0 && input_faults == 0 && case_faults == 0 {
        Ok(())
    } else {
        Err(HoldoutError::new(format!(
            "strict V2 policy-comparison gate rejected {failures} semantic failures, {input_faults} input faults, and {case_faults} policy-artifact faults; inspect the already-written receipts"
        )))
    }
}

/// Require every structurally frozen case to have two ready, correct policy
/// artifacts before it may enter the timing campaign.
pub fn enforce_aot_selected_end_v2_timing_readiness(
    report: &AotSelectedEndV2CorrectnessReport,
) -> Result<(), HoldoutError> {
    if report.host.disposition != AotSelectedEndDisposition::Ready {
        return Err(HoldoutError::new(
            "V2 timing requires a ready authenticated host",
        ));
    }
    if report.frozen_eligible_case_ids.is_empty() {
        return Err(HoldoutError::new(
            "V2 timing requires at least one structurally eligible frozen case",
        ));
    }
    let eligible = report
        .frozen_eligible_case_ids
        .iter()
        .map(String::as_str)
        .collect::<BTreeSet<_>>();
    let mut missing = Vec::new();
    for case in &report.cases {
        if !eligible.contains(case.case_id.as_str()) {
            continue;
        }
        if case.eligibility != AotSelectedEndV2Eligibility::StructurallyEligible
            || !case.force_structurally_eligible.route_selected
            || case.automatic.build.disposition != AotSelectedEndDisposition::Ready
            || case.force_structurally_eligible.build.disposition
                != AotSelectedEndDisposition::Ready
        {
            missing.push(format!("{}(artifact-closure)", case.case_id));
            continue;
        }
        for policy in AotSelectedEndV2Policy::ALL {
            for window_kind in [
                AotSelectedEndWindowKind::Full,
                AotSelectedEndWindowKind::MidscanNonzeroBounded,
            ] {
                if !report.comparisons.iter().any(|receipt| {
                    receipt.policy == policy
                        && receipt.comparison.case_id == case.case_id
                        && receipt.comparison.window_kind == window_kind
                        && receipt.comparison.status == AotSelectedEndComparisonStatus::Pass
                }) {
                    missing.push(format!("{}({policy:?},{window_kind:?})", case.case_id));
                }
            }
        }
        if report.comparisons.iter().any(|receipt| {
            receipt.comparison.case_id == case.case_id
                && receipt.comparison.status != AotSelectedEndComparisonStatus::Pass
        }) {
            missing.push(format!("{}(non-pass-window)", case.case_id));
        }
    }
    if missing.is_empty() {
        Ok(())
    } else {
        Err(HoldoutError::new(format!(
            "V2 timing readiness rejected frozen eligible cases: {missing:?}"
        )))
    }
}

fn v2_readiness_description(report: &AotSelectedEndV2CorrectnessReport) -> String {
    format!(
        "validated strict gate; ready host; {} structurally eligible cases frozen solely from forced supplemental receipts; both policy artifacts ready and every full/bounded receipt passing for each eligible case",
        report.frozen_eligible_case_ids.len()
    )
}

/// Rebuild both policy artifacts and close every authenticated case, window,
/// structural receipt, identity edge, coverage counter, and digest.
#[allow(
    clippy::too_many_lines,
    reason = "one validator deliberately closes policy leakage, structural eligibility, two-artifact semantics, provenance, coverage, and digests together"
)]
pub fn validate_aot_selected_end_v2_correctness(
    authenticated: &AuthenticatedSuite,
    report: &AotSelectedEndV2CorrectnessReport,
) -> Result<(), HoldoutError> {
    if report.schema != AOT_SELECTED_END_V2_CORRECTNESS_SCHEMA
        || report.suite_id != authenticated.manifest.suite_id
        || report.suite_sha256 != authenticated.suite_sha256
        || report.json_schema_sha256 != authenticated.json_schema_sha256
        || report.expanded_inputs_sha256 != authenticated.expanded_inputs_sha256
        || report.candidate_identity != V2_CORRECTNESS_CANDIDATE_IDENTITY
        || report.oracle_identity != V2_CORRECTNESS_ORACLE_IDENTITY
        || report.eligibility_identity != V2_ELIGIBILITY_IDENTITY
        || report.target_arch != std::env::consts::ARCH
        || report.target_os != std::env::consts::OS
        || report.target_pointer_width != usize::BITS
        || report.limit_policy != selected_end_limit_policy()
    {
        return Err(HoldoutError::new(
            "V2 correctness authentication binding is invalid",
        ));
    }
    let inputs = aot_search_inputs(authenticated)?;
    if report.window_matrix_sha256 != aot_window_matrix_sha256(authenticated, &inputs)? {
        return Err(HoldoutError::new(
            "V2 correctness window-matrix digest is invalid",
        ));
    }
    let expected_comparisons = inputs
        .len()
        .checked_mul(AotSelectedEndV2Policy::ALL.len())
        .ok_or_else(|| HoldoutError::new("V2 validation matrix length overflow"))?;
    if report.cases.len() != authenticated.manifest.cases.len()
        || report.comparisons.len() != expected_comparisons
    {
        return Err(HoldoutError::new(
            "V2 correctness matrix has the wrong dimensions",
        ));
    }
    let target = validate_v2_host(&report.host)?;
    let mut eligible_case_ids = Vec::new();
    let mut comparison_index = 0_usize;

    for (spec, recorded_case) in authenticated.manifest.cases.iter().zip(&report.cases) {
        let input_count = authenticated
            .inputs
            .iter()
            .filter(|input| input.case_id == spec.id)
            .count();
        let case_inputs = inputs
            .iter()
            .filter(|input| input.case_id == spec.id)
            .collect::<Vec<_>>();
        if recorded_case.case_id != spec.id
            || recorded_case.family != spec.family
            || recorded_case.labels != spec.labels
            || recorded_case.pattern_sha256 != crate::sha256(spec.pattern.as_bytes())
            || recorded_case.input_count != input_count
            || recorded_case.search_window_count != case_inputs.len()
        {
            return Err(HoldoutError::new(format!(
                "V2 case {} does not close over its authenticated specification",
                spec.id
            )));
        }
        let rebuilt_automatic = build_v2_policy_artifact(
            spec,
            input_count,
            case_inputs.len(),
            AotSelectedEndV2Policy::Automatic,
            target,
            &report.host,
        );
        let rebuilt_forced = build_v2_policy_artifact(
            spec,
            input_count,
            case_inputs.len(),
            AotSelectedEndV2Policy::ForceStructurallyEligible,
            target,
            &report.host,
        );
        if recorded_case.automatic != rebuilt_automatic.receipt
            || recorded_case.force_structurally_eligible != rebuilt_forced.receipt
        {
            return Err(HoldoutError::new(format!(
                "V2 case {} policy artifact receipt does not reproduce",
                spec.id
            )));
        }
        let eligibility = forced_eligibility(&rebuilt_forced.receipt);
        if recorded_case.eligibility != eligibility {
            return Err(HoldoutError::new(format!(
                "V2 case {} eligibility is not derived solely from its forced supplemental receipt",
                spec.id
            )));
        }
        if eligibility == AotSelectedEndV2Eligibility::StructurallyEligible {
            eligible_case_ids.push(spec.id.clone());
        }

        let oracle = independent_oracle(&spec.pattern).map_err(|error| {
            HoldoutError::new(format!("rebuild V2 oracle for {}: {error}", spec.id))
        })?;
        for input in case_inputs {
            let (oracle_kind, oracle_end) = independent_end(&oracle, input);
            for (policy, rebuilt) in [
                (AotSelectedEndV2Policy::Automatic, &rebuilt_automatic),
                (
                    AotSelectedEndV2Policy::ForceStructurallyEligible,
                    &rebuilt_forced,
                ),
            ] {
                let expected = AotSelectedEndV2ComparisonReceipt {
                    policy,
                    route_selected: rebuilt.receipt.route_selected,
                    comparison: compare_input(
                        input,
                        oracle_kind,
                        oracle_end,
                        &rebuilt.receipt.build,
                        rebuilt.portable.as_ref(),
                        rebuilt.published.as_ref(),
                    ),
                };
                let recorded = report.comparisons.get(comparison_index).ok_or_else(|| {
                    HoldoutError::new("V2 comparison matrix ended before its authenticated input")
                })?;
                if *recorded != expected {
                    return Err(HoldoutError::new(format!(
                        "V2 comparison {}:{}:{:?}:{policy:?} does not reproduce",
                        input.case_id, input.input_ordinal, input.window_kind
                    )));
                }
                comparison_index = comparison_index
                    .checked_add(1)
                    .ok_or_else(|| HoldoutError::new("V2 comparison index overflow"))?;
            }
        }
    }
    if comparison_index != report.comparisons.len()
        || eligible_case_ids != report.frozen_eligible_case_ids
    {
        return Err(HoldoutError::new(
            "V2 comparison order or frozen eligible case list is invalid",
        ));
    }
    let unique_eligible = report
        .frozen_eligible_case_ids
        .iter()
        .collect::<BTreeSet<_>>();
    if unique_eligible.len() != report.frozen_eligible_case_ids.len() {
        return Err(HoldoutError::new(
            "V2 frozen eligible case list contains duplicates",
        ));
    }
    let expected_eligibility_sha256 = eligibility_sha256(
        authenticated,
        &report.window_matrix_sha256,
        &report.host,
        &report.limit_policy,
        &report.cases,
        &report.frozen_eligible_case_ids,
    )?;
    if report.eligibility_sha256 != expected_eligibility_sha256 {
        return Err(HoldoutError::new(
            "V2 frozen eligibility digest does not recompute",
        ));
    }
    let coverage = v2_coverage(
        authenticated.inputs.len(),
        &report.cases,
        &report.comparisons,
    );
    if report.coverage != coverage {
        return Err(HoldoutError::new(
            "V2 correctness coverage does not recompute",
        ));
    }
    let provenance_bytes = serde_json::to_vec(&(&report.host, &report.provenance))
        .map_err(|error| HoldoutError::new(format!("recompute V2 provenance: {error}")))?;
    if report.provenance_sha256 != crate::sha256(&provenance_bytes) {
        return Err(HoldoutError::new(
            "V2 correctness provenance digest does not recompute",
        ));
    }
    let receipt_bytes = serde_json::to_vec(&(
        &report.limit_policy,
        &report.eligibility_sha256,
        &report.frozen_eligible_case_ids,
        &report.cases,
        &report.comparisons,
    ))
    .map_err(|error| HoldoutError::new(format!("recompute V2 receipts: {error}")))?;
    if report.receipts_sha256 != crate::sha256(&receipt_bytes) {
        return Err(HoldoutError::new(
            "V2 correctness receipt digest does not recompute",
        ));
    }
    validate_v2_provenance(report)?;
    Ok(())
}

fn validate_v2_host(host: &AotSelectedEndHostReceipt) -> Result<Option<Target>, HoldoutError> {
    match host.disposition {
        AotSelectedEndDisposition::Ready => {
            if host.reason_code.is_some() || host.reason.is_some() {
                return Err(HoldoutError::new("ready V2 host retained a reason"));
            }
            Ok(Some(target_from_receipt(
                host.target
                    .as_ref()
                    .ok_or_else(|| HoldoutError::new("ready V2 host omitted its target"))?,
            )?))
        }
        AotSelectedEndDisposition::Declined => {
            if host.target.is_some() || host.reason_code.is_none() || host.reason.is_none() {
                return Err(HoldoutError::new(
                    "declined V2 host has invalid target/reason closure",
                ));
            }
            Ok(None)
        }
        AotSelectedEndDisposition::Fault => {
            if host.reason_code.is_none() || host.reason.is_none() {
                return Err(HoldoutError::new("faulted V2 host omitted its reason"));
            }
            if let Some(receipt) = &host.target {
                let _ = target_from_receipt(receipt)?;
            }
            Ok(None)
        }
    }
}

fn validate_v2_provenance(report: &AotSelectedEndV2CorrectnessReport) -> Result<(), HoldoutError> {
    for digest in [
        &report.provenance_sha256,
        &report.eligibility_sha256,
        &report.receipts_sha256,
        &report.provenance.source_status_sha256_at_build,
        &report.provenance.source_status_sha256_at_run,
        &report.provenance.source_diff_sha256_at_build,
        &report.provenance.source_diff_sha256_at_run,
        &report.provenance.source_untracked_sha256_at_build,
        &report.provenance.source_untracked_sha256_at_run,
        &report.provenance.executable_sha256,
    ] {
        if digest.len() != 64 || !digest.bytes().all(|byte| byte.is_ascii_hexdigit()) {
            return Err(HoldoutError::new("invalid V2 SHA-256 evidence"));
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
            "V2 provenance does not bind the executable to the runtime source snapshot",
        ));
    }
    Ok(())
}

/// Phase for the hot paired V2 schedule.
#[derive(Clone, Copy, Debug, Deserialize, Serialize, Eq, Ord, PartialEq, PartialOrd)]
#[serde(rename_all = "kebab-case")]
pub enum AotSelectedEndV2SchedulePhase {
    Warmup,
    Measured,
}

/// One frozen-eligible window in a deterministic paired sweep.
#[derive(Clone, Debug, Deserialize, Serialize, Eq, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct AotSelectedEndV2ScheduledInput {
    pub input_index: usize,
    pub schedule_position: usize,
    pub case_id: String,
    pub input_ordinal: usize,
    pub window_kind: AotSelectedEndWindowKind,
    pub haystack_sha256: String,
    pub window_start: usize,
    pub window_end: usize,
    pub first_policy: AotSelectedEndV2Policy,
}

/// One complete permutation of every frozen-eligible window.
#[derive(Clone, Debug, Deserialize, Serialize, Eq, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct AotSelectedEndV2ScheduledSweep {
    pub phase: AotSelectedEndV2SchedulePhase,
    pub repetition_index: usize,
    pub entries: Vec<AotSelectedEndV2ScheduledInput>,
}

/// Fully recorded deterministic, reversal-counterbalanced schedule.
#[derive(Clone, Debug, Deserialize, Serialize, Eq, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct AotSelectedEndV2ScheduleReceipt {
    pub schema: String,
    pub binding_sha256: String,
    pub seed_sha256: String,
    pub algorithm: String,
    pub warmup: Vec<AotSelectedEndV2ScheduledSweep>,
    pub measured: Vec<AotSelectedEndV2ScheduledSweep>,
}

/// Checked timing cardinality computed before schedule or timing allocation.
#[derive(Clone, Debug, Deserialize, Serialize, Eq, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct AotSelectedEndV2ObservationBudgetReceipt {
    pub schema: String,
    pub maximum_timing_observations: usize,
    pub frozen_eligible_search_windows: usize,
    pub frozen_eligible_case_patterns: usize,
    pub warmup_sweeps: usize,
    pub measured_sweeps: usize,
    pub planned_paired_points: usize,
    pub planned_paired_policy_observations: usize,
    pub planned_setup_observations: usize,
    pub planned_total_timing_observations: usize,
}

/// Terminal state of one V2 setup or hot search observation.
#[derive(Clone, Copy, Debug, Deserialize, Serialize, Eq, Ord, PartialEq, PartialOrd)]
#[serde(rename_all = "kebab-case")]
pub enum AotSelectedEndV2TimingTerminal {
    Executed,
    Declined,
    Mismatch,
    Fault,
}

/// Compile/publication timing kept outside every hot search sample.
#[derive(Clone, Debug, Deserialize, Serialize, Eq, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct AotSelectedEndV2HotSetupReceipt {
    pub policy: AotSelectedEndV2Policy,
    pub case_id: String,
    pub route_selected: bool,
    pub terminal: AotSelectedEndV2TimingTerminal,
    pub compile_ns: Option<u64>,
    pub publish_ns: Option<u64>,
    pub setup_ns: Option<u64>,
    pub compiler_object_sha256: Option<String>,
    pub artifact_binding_sha256: Option<String>,
    pub reason_code: Option<String>,
    pub reason: Option<String>,
}

/// One call on a policy matcher constructed outside the hot loop.
#[derive(Clone, Debug, Deserialize, Serialize, Eq, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct AotSelectedEndV2HotObservation {
    pub terminal: AotSelectedEndV2TimingTerminal,
    pub search_ns: Option<u64>,
    pub scan_attempted: bool,
    pub actual_end: Option<usize>,
    pub reason_code: Option<String>,
    pub reason: Option<String>,
}

/// Adjacent Automatic/forced observations for one identical window.
#[derive(Clone, Debug, Deserialize, Serialize, Eq, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct AotSelectedEndV2HotTimingPoint {
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
    pub first_policy: AotSelectedEndV2Policy,
    pub automatic: AotSelectedEndV2HotObservation,
    pub force_structurally_eligible: AotSelectedEndV2HotObservation,
}

/// Recomputable timing coverage.
#[derive(Clone, Debug, Default, Deserialize, Serialize, Eq, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct AotSelectedEndV2PerformanceCoverage {
    pub retained_case_patterns: usize,
    pub structurally_ineligible_cases: usize,
    pub compile_declined_cases: usize,
    pub faulted_eligibility_cases: usize,
    pub frozen_eligible_case_patterns: usize,
    pub frozen_eligible_search_windows: usize,
    pub setup_receipts: usize,
    pub warmup_paired_points: usize,
    pub measured_paired_points: usize,
    pub setup_by_policy_terminal:
        BTreeMap<AotSelectedEndV2Policy, BTreeMap<AotSelectedEndV2TimingTerminal, usize>>,
    pub warmup_by_policy_terminal:
        BTreeMap<AotSelectedEndV2Policy, BTreeMap<AotSelectedEndV2TimingTerminal, usize>>,
    pub measured_by_policy_terminal:
        BTreeMap<AotSelectedEndV2Policy, BTreeMap<AotSelectedEndV2TimingTerminal, usize>>,
}

/// Non-normative paired hot comparison. Correctness and eligibility are
/// immutable inputs, never outputs of this report.
#[derive(Clone, Debug, Deserialize, Serialize, Eq, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct AotSelectedEndV2PerformanceReport {
    pub schema: String,
    pub suite_id: String,
    pub suite_sha256: String,
    pub json_schema_sha256: String,
    pub expanded_inputs_sha256: String,
    pub window_matrix_sha256: String,
    pub correctness_receipts_sha256: String,
    pub correctness_provenance_sha256: String,
    pub frozen_eligibility_sha256: String,
    pub frozen_eligible_case_ids: Vec<String>,
    pub target_arch: String,
    pub target_os: String,
    pub target_pointer_width: u32,
    pub host: AotSelectedEndHostReceipt,
    pub provenance: AotSelectedEndProvenanceReceipt,
    pub policy: TimingPolicy,
    pub limit_policy: AotSelectedEndLimitPolicyReceipt,
    pub observation_budget: AotSelectedEndV2ObservationBudgetReceipt,
    pub normative: bool,
    pub planner_feedback_permitted: bool,
    pub eligibility_identity: String,
    pub hot_measurement_scope: String,
    pub pairing_schedule: String,
    pub readiness_floor: String,
    pub schedule: AotSelectedEndV2ScheduleReceipt,
    pub timing_receipts_sha256: String,
    pub coverage: AotSelectedEndV2PerformanceCoverage,
    pub hot_setups: Vec<AotSelectedEndV2HotSetupReceipt>,
    pub warmup_points: Vec<AotSelectedEndV2HotTimingPoint>,
    pub measured_points: Vec<AotSelectedEndV2HotTimingPoint>,
}

#[derive(Debug)]
struct LiveV2HotArtifact {
    setup: AotSelectedEndV2HotSetupReceipt,
    published: Option<PublishedSelectedEnd>,
}

/// Run only the separately requested timing campaign. All validation,
/// eligibility freezing, strict gates, readiness checks, and the observation
/// cap complete before the first `Instant` is constructed.
#[allow(
    clippy::too_many_lines,
    reason = "the paired hot transaction keeps pre-clock gates, schedule, setup, observations, and receipt binding in one auditable function"
)]
pub fn run_aot_selected_end_v2_performance(
    authenticated: &AuthenticatedSuite,
    correctness: &AotSelectedEndV2CorrectnessReport,
) -> Result<AotSelectedEndV2PerformanceReport, HoldoutError> {
    let live_provenance = collect_provenance()?;
    if live_provenance != correctness.provenance {
        return Err(HoldoutError::new(
            "source/build/executable provenance changed after V2 correctness and before timing",
        ));
    }
    validate_aot_selected_end_v2_correctness(authenticated, correctness)?;
    enforce_aot_selected_end_v2_strict_gate(correctness)?;
    enforce_aot_selected_end_v2_timing_readiness(correctness)?;
    let policy = authenticated.manifest.timing;
    let observation_budget = v2_observation_budget(
        correctness.coverage.frozen_eligible_search_windows,
        correctness.coverage.frozen_eligible_cases,
        policy,
    )?;

    let target = verified_performance_target(&correctness.host)?.ok_or_else(|| {
        HoldoutError::new("ready V2 timing correctness report did not yield a target")
    })?;
    let inputs = aot_search_inputs(authenticated)?;
    if aot_window_matrix_sha256(authenticated, &inputs)? != correctness.window_matrix_sha256 {
        return Err(HoldoutError::new(
            "V2 timing window matrix differs from correctness",
        ));
    }
    let eligible_case_ids = correctness
        .frozen_eligible_case_ids
        .iter()
        .map(String::as_str)
        .collect::<BTreeSet<_>>();
    let eligible_input_indices = inputs
        .iter()
        .enumerate()
        .filter(|(_, input)| eligible_case_ids.contains(input.case_id.as_str()))
        .map(|(index, _)| index)
        .collect::<Vec<_>>();
    if eligible_input_indices.len() != correctness.coverage.frozen_eligible_search_windows {
        return Err(HoldoutError::new(
            "V2 frozen eligible window count does not reconstruct before timing",
        ));
    }
    let expected_ends = v2_expected_ends(correctness, &inputs, &eligible_input_indices)?;
    let schedule = build_v2_schedule(
        authenticated,
        correctness,
        &inputs,
        &eligible_input_indices,
        policy,
    )?;

    let setup_capacity = correctness
        .coverage
        .frozen_eligible_cases
        .checked_mul(AotSelectedEndV2Policy::ALL.len())
        .ok_or_else(|| HoldoutError::new("V2 setup count overflow"))?;
    let mut hot_setups = Vec::new();
    hot_setups
        .try_reserve_exact(setup_capacity)
        .map_err(|_| HoldoutError::new("allocate V2 setup receipts"))?;
    let mut live_by_case = BTreeMap::new();
    for (spec, case_receipt) in authenticated.manifest.cases.iter().zip(&correctness.cases) {
        if !eligible_case_ids.contains(spec.id.as_str()) {
            continue;
        }
        let automatic = setup_v2_hot_artifact(
            spec,
            target,
            AotSelectedEndV2Policy::Automatic,
            &case_receipt.automatic,
        );
        let forced = setup_v2_hot_artifact(
            spec,
            target,
            AotSelectedEndV2Policy::ForceStructurallyEligible,
            &case_receipt.force_structurally_eligible,
        );
        hot_setups.push(automatic.setup.clone());
        hot_setups.push(forced.setup.clone());
        if live_by_case
            .insert(spec.id.clone(), (automatic, forced))
            .is_some()
        {
            return Err(HoldoutError::new("duplicate V2 hot case setup"));
        }
    }

    let warmup_capacity = eligible_input_indices
        .len()
        .checked_mul(schedule.warmup.len())
        .ok_or_else(|| HoldoutError::new("V2 warmup point count overflow"))?;
    let measured_capacity = eligible_input_indices
        .len()
        .checked_mul(schedule.measured.len())
        .ok_or_else(|| HoldoutError::new("V2 measured point count overflow"))?;
    let mut warmup_points = Vec::new();
    warmup_points
        .try_reserve_exact(warmup_capacity)
        .map_err(|_| HoldoutError::new("allocate V2 warmup receipts"))?;
    let mut measured_points = Vec::new();
    measured_points
        .try_reserve_exact(measured_capacity)
        .map_err(|_| HoldoutError::new("allocate V2 measured receipts"))?;
    for sweep in &schedule.warmup {
        for entry in &sweep.entries {
            let input = v2_scheduled_input(&inputs, entry)?;
            let live = live_by_case
                .get(&input.case_id)
                .ok_or_else(|| HoldoutError::new("V2 schedule omitted its live case"))?;
            warmup_points.push(run_v2_hot_pair(
                entry,
                sweep.repetition_index,
                input,
                *expected_ends
                    .get(&entry.input_index)
                    .ok_or_else(|| HoldoutError::new("V2 warmup omitted expected end"))?,
                &live.0,
                &live.1,
            ));
        }
    }
    for sweep in &schedule.measured {
        for entry in &sweep.entries {
            let input = v2_scheduled_input(&inputs, entry)?;
            let live = live_by_case
                .get(&input.case_id)
                .ok_or_else(|| HoldoutError::new("V2 schedule omitted its live case"))?;
            measured_points.push(run_v2_hot_pair(
                entry,
                sweep.repetition_index,
                input,
                *expected_ends
                    .get(&entry.input_index)
                    .ok_or_else(|| HoldoutError::new("V2 measurement omitted expected end"))?,
                &live.0,
                &live.1,
            ));
        }
    }
    let coverage =
        v2_performance_coverage(correctness, &hot_setups, &warmup_points, &measured_points);
    let timing_bytes = serde_json::to_vec(&(
        &correctness.limit_policy,
        &correctness.eligibility_sha256,
        &observation_budget,
        &schedule,
        &hot_setups,
        &warmup_points,
        &measured_points,
    ))
    .map_err(|error| HoldoutError::new(format!("serialize V2 timing receipts: {error}")))?;
    let report = AotSelectedEndV2PerformanceReport {
        schema: AOT_SELECTED_END_V2_PERFORMANCE_SCHEMA.to_string(),
        suite_id: authenticated.manifest.suite_id.clone(),
        suite_sha256: authenticated.suite_sha256.clone(),
        json_schema_sha256: authenticated.json_schema_sha256.clone(),
        expanded_inputs_sha256: authenticated.expanded_inputs_sha256.clone(),
        window_matrix_sha256: correctness.window_matrix_sha256.clone(),
        correctness_receipts_sha256: correctness.receipts_sha256.clone(),
        correctness_provenance_sha256: correctness.provenance_sha256.clone(),
        frozen_eligibility_sha256: correctness.eligibility_sha256.clone(),
        frozen_eligible_case_ids: correctness.frozen_eligible_case_ids.clone(),
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
        eligibility_identity: V2_ELIGIBILITY_IDENTITY.to_string(),
        hot_measurement_scope: V2_HOT_MEASUREMENT_SCOPE.to_string(),
        pairing_schedule: V2_PAIRING_DESCRIPTION.to_string(),
        readiness_floor: v2_readiness_description(correctness),
        schedule,
        timing_receipts_sha256: crate::sha256(&timing_bytes),
        coverage,
        hot_setups,
        warmup_points,
        measured_points,
    };
    validate_aot_selected_end_v2_performance(authenticated, correctness, &report)?;
    Ok(report)
}

fn v2_observation_budget(
    windows: usize,
    cases: usize,
    policy: TimingPolicy,
) -> Result<AotSelectedEndV2ObservationBudgetReceipt, HoldoutError> {
    let sweeps = policy
        .warmup_iterations
        .checked_add(policy.measured_iterations)
        .ok_or_else(|| HoldoutError::new("V2 timing sweep count overflow"))?;
    let planned_paired_points = windows
        .checked_mul(sweeps)
        .ok_or_else(|| HoldoutError::new("V2 paired point count overflow"))?;
    let planned_paired_policy_observations = planned_paired_points
        .checked_mul(AotSelectedEndV2Policy::ALL.len())
        .ok_or_else(|| HoldoutError::new("V2 paired observation count overflow"))?;
    let planned_setup_observations = cases
        .checked_mul(AotSelectedEndV2Policy::ALL.len())
        .ok_or_else(|| HoldoutError::new("V2 setup observation count overflow"))?;
    let planned_total_timing_observations = planned_paired_policy_observations
        .checked_add(planned_setup_observations)
        .ok_or_else(|| HoldoutError::new("V2 total observation count overflow"))?;
    if planned_total_timing_observations > MAX_V2_TIMING_OBSERVATIONS {
        return Err(HoldoutError::new(format!(
            "V2 timing observation cap exceeded: planned={planned_total_timing_observations}, maximum={MAX_V2_TIMING_OBSERVATIONS}"
        )));
    }
    Ok(AotSelectedEndV2ObservationBudgetReceipt {
        schema: V2_OBSERVATION_BUDGET_SCHEMA.to_string(),
        maximum_timing_observations: MAX_V2_TIMING_OBSERVATIONS,
        frozen_eligible_search_windows: windows,
        frozen_eligible_case_patterns: cases,
        warmup_sweeps: policy.warmup_iterations,
        measured_sweeps: policy.measured_iterations,
        planned_paired_points,
        planned_paired_policy_observations,
        planned_setup_observations,
        planned_total_timing_observations,
    })
}

fn v2_expected_ends(
    correctness: &AotSelectedEndV2CorrectnessReport,
    inputs: &[AotSelectedEndSearchInput],
    eligible_input_indices: &[usize],
) -> Result<BTreeMap<usize, Option<usize>>, HoldoutError> {
    let mut expected = BTreeMap::new();
    for &input_index in eligible_input_indices {
        let input = inputs
            .get(input_index)
            .ok_or_else(|| HoldoutError::new("V2 eligible input index is invalid"))?;
        let mut policy_ends = Vec::new();
        for policy in AotSelectedEndV2Policy::ALL {
            let matching = correctness
                .comparisons
                .iter()
                .filter(|receipt| {
                    let comparison = &receipt.comparison;
                    receipt.policy == policy
                        && comparison.case_id == input.case_id
                        && comparison.input_ordinal == input.input_ordinal
                        && comparison.window_kind == input.window_kind
                        && comparison.haystack_sha256 == crate::sha256(&input.haystack)
                        && comparison.window_start == input.window_start
                        && comparison.window_end == input.window_end
                })
                .collect::<Vec<_>>();
            if matching.len() != 1 {
                return Err(HoldoutError::new(format!(
                    "V2 expected-end lookup found {} receipts for {}:{}:{:?}:{policy:?}",
                    matching.len(),
                    input.case_id,
                    input.input_ordinal,
                    input.window_kind
                )));
            }
            let receipt = matching[0];
            if receipt.comparison.status != AotSelectedEndComparisonStatus::Pass
                || !receipt.comparison.portable_call_attempted
                || !receipt.comparison.native_call_attempted
                || receipt.comparison.actual_end != receipt.comparison.expected_end
                || receipt.comparison.expected_end != receipt.comparison.independent_end
            {
                return Err(HoldoutError::new(format!(
                    "V2 eligible expected-end receipt is not a three-way pass for {}:{}:{:?}:{policy:?}",
                    input.case_id, input.input_ordinal, input.window_kind
                )));
            }
            policy_ends.push(receipt.comparison.expected_end);
        }
        if policy_ends[0] != policy_ends[1] {
            return Err(HoldoutError::new(format!(
                "V2 policies have different frozen expectations for {}:{}:{:?}",
                input.case_id, input.input_ordinal, input.window_kind
            )));
        }
        if expected.insert(input_index, policy_ends[0]).is_some() {
            return Err(HoldoutError::new("duplicate V2 eligible input index"));
        }
    }
    Ok(expected)
}

fn build_v2_schedule(
    authenticated: &AuthenticatedSuite,
    correctness: &AotSelectedEndV2CorrectnessReport,
    inputs: &[AotSelectedEndSearchInput],
    eligible_input_indices: &[usize],
    policy: TimingPolicy,
) -> Result<AotSelectedEndV2ScheduleReceipt, HoldoutError> {
    let binding_bytes = serde_json::to_vec(&(
        V2_SCHEDULE_SCHEMA,
        &authenticated.suite_sha256,
        &authenticated.expanded_inputs_sha256,
        &correctness.window_matrix_sha256,
        &correctness.receipts_sha256,
        &correctness.provenance_sha256,
        &correctness.eligibility_sha256,
        &correctness.frozen_eligible_case_ids,
        eligible_input_indices,
        policy,
    ))
    .map_err(|error| HoldoutError::new(format!("serialize V2 schedule binding: {error}")))?;
    let binding_sha256 = crate::sha256(&binding_bytes);
    let seed_bytes = serde_json::to_vec(&(
        "fre-holdout-aot-selected-end-v2-schedule-seed-v1",
        &binding_sha256,
    ))
    .map_err(|error| HoldoutError::new(format!("serialize V2 schedule seed: {error}")))?;
    let seed_sha256 = crate::sha256(&seed_bytes);
    let seed = u64::from_str_radix(
        seed_sha256
            .get(..16)
            .ok_or_else(|| HoldoutError::new("V2 schedule seed digest is truncated"))?,
        16,
    )
    .map_err(|error| HoldoutError::new(format!("decode V2 schedule seed: {error}")))?;
    Ok(AotSelectedEndV2ScheduleReceipt {
        schema: V2_SCHEDULE_SCHEMA.to_string(),
        binding_sha256,
        seed_sha256,
        algorithm: "splitmix64-fisher-yates-v1; independently domain-separated warmup/measured pairs; even sweep seeded permutation, following odd sweep exact reverse; first policy=(global-input-index+repetition-index) parity".to_string(),
        warmup: v2_scheduled_sweeps(
            inputs,
            eligible_input_indices,
            AotSelectedEndV2SchedulePhase::Warmup,
            policy.warmup_iterations,
            seed ^ 0x7a39_6d81_2c54_f0b7,
        )?,
        measured: v2_scheduled_sweeps(
            inputs,
            eligible_input_indices,
            AotSelectedEndV2SchedulePhase::Measured,
            policy.measured_iterations,
            seed ^ 0xc54d_139b_a068_2e71,
        )?,
    })
}

fn v2_scheduled_sweeps(
    inputs: &[AotSelectedEndSearchInput],
    eligible_input_indices: &[usize],
    phase: AotSelectedEndV2SchedulePhase,
    repetitions: usize,
    seed: u64,
) -> Result<Vec<AotSelectedEndV2ScheduledSweep>, HoldoutError> {
    let mut sweeps = Vec::new();
    sweeps
        .try_reserve_exact(repetitions)
        .map_err(|_| HoldoutError::new("allocate V2 schedule sweeps"))?;
    let mut even_permutation = Vec::new();
    for repetition_index in 0..repetitions {
        let permutation = if repetition_index % 2 == 0 {
            let mut values = eligible_input_indices.to_vec();
            let pair_index = repetition_index / 2;
            v2_fisher_yates(
                &mut values,
                V2ScheduleRng(seed ^ u64::try_from(pair_index).unwrap_or(u64::MAX)),
            );
            even_permutation.clone_from(&values);
            values
        } else {
            let mut values = even_permutation.clone();
            values.reverse();
            values
        };
        let mut entries = Vec::new();
        entries
            .try_reserve_exact(permutation.len())
            .map_err(|_| HoldoutError::new("allocate V2 scheduled entries"))?;
        for (schedule_position, &input_index) in permutation.iter().enumerate() {
            let input = inputs
                .get(input_index)
                .ok_or_else(|| HoldoutError::new("V2 schedule input index is invalid"))?;
            entries.push(AotSelectedEndV2ScheduledInput {
                input_index,
                schedule_position,
                case_id: input.case_id.clone(),
                input_ordinal: input.input_ordinal,
                window_kind: input.window_kind,
                haystack_sha256: crate::sha256(&input.haystack),
                window_start: input.window_start,
                window_end: input.window_end,
                first_policy: if input_index.wrapping_add(repetition_index) & 1 == 0 {
                    AotSelectedEndV2Policy::Automatic
                } else {
                    AotSelectedEndV2Policy::ForceStructurallyEligible
                },
            });
        }
        sweeps.push(AotSelectedEndV2ScheduledSweep {
            phase,
            repetition_index,
            entries,
        });
    }
    Ok(sweeps)
}

#[derive(Clone, Copy)]
struct V2ScheduleRng(u64);

impl V2ScheduleRng {
    fn next(&mut self) -> u64 {
        self.0 = self.0.wrapping_add(0x9e37_79b9_7f4a_7c15);
        let mut value = self.0;
        value = (value ^ (value >> 30)).wrapping_mul(0xbf58_476d_1ce4_e5b9);
        value = (value ^ (value >> 27)).wrapping_mul(0x94d0_49bb_1331_11eb);
        value ^ (value >> 31)
    }

    fn below(&mut self, upper: usize) -> usize {
        if upper <= 1 {
            return 0;
        }
        let upper_u64 = u64::try_from(upper).unwrap_or(u64::MAX);
        let threshold = upper_u64
            .wrapping_neg()
            .checked_rem(upper_u64)
            .expect("the V2 schedule bound is nonzero");
        loop {
            let candidate = self.next();
            if candidate >= threshold {
                let index = candidate
                    .checked_rem(upper_u64)
                    .expect("the V2 schedule bound is nonzero");
                return usize::try_from(index).expect("the bounded V2 schedule index fits usize");
            }
        }
    }
}

fn v2_fisher_yates(values: &mut [usize], mut rng: V2ScheduleRng) {
    for end in (1..values.len()).rev() {
        let selected = rng.below(
            end.checked_add(1)
                .expect("a V2 schedule slice index has a successor"),
        );
        values.swap(end, selected);
    }
}

fn v2_scheduled_input<'a>(
    inputs: &'a [AotSelectedEndSearchInput],
    entry: &AotSelectedEndV2ScheduledInput,
) -> Result<&'a AotSelectedEndSearchInput, HoldoutError> {
    let input = inputs
        .get(entry.input_index)
        .ok_or_else(|| HoldoutError::new("V2 scheduled input index is invalid"))?;
    if entry.case_id != input.case_id
        || entry.input_ordinal != input.input_ordinal
        || entry.window_kind != input.window_kind
        || entry.haystack_sha256 != crate::sha256(&input.haystack)
        || entry.window_start != input.window_start
        || entry.window_end != input.window_end
    {
        return Err(HoldoutError::new(
            "V2 scheduled input does not close over its authenticated window",
        ));
    }
    Ok(input)
}

#[allow(
    clippy::too_many_lines,
    reason = "compile, receipt comparison, publication, and their separate timing fields form one setup transaction"
)]
fn setup_v2_hot_artifact(
    case: &CaseSpec,
    target: Target,
    policy: AotSelectedEndV2Policy,
    expected: &AotSelectedEndV2PolicyArtifactReceipt,
) -> LiveV2HotArtifact {
    let setup_started = Instant::now();
    let compile_started = Instant::now();
    let compiled = catch_unwind(AssertUnwindSafe(|| {
        compile_v2(v2_request(case, target, policy))
    }));
    let compile_ns = super::elapsed_ns(compile_started);
    let compiled = match compiled {
        Err(_) => {
            return v2_hot_setup_failure(
                policy,
                case,
                false,
                AotSelectedEndV2TimingTerminal::Fault,
                Some(compile_ns),
                None,
                Some(super::elapsed_ns(setup_started)),
                None,
                "timing.compile-v2.panic",
                "CompileRequestV2 hot setup panicked".to_string(),
            );
        }
        Ok(Err(error)) => {
            return v2_hot_setup_failure(
                policy,
                case,
                false,
                v2_disposition_terminal(compile_error_disposition(&error)),
                Some(compile_ns),
                None,
                Some(super::elapsed_ns(setup_started)),
                None,
                &compile_error_code(&error).replace("compile.", "timing.compile-v2."),
                error.to_string(),
            );
        }
        Ok(Ok(compiled)) => compiled,
    };
    let compiler_receipt = compiler_evidence(compiled.compiled());
    let supplemental = match v2_supplemental_evidence(&compiled, policy) {
        Ok(evidence) => evidence,
        Err(error) => {
            return v2_hot_setup_failure(
                policy,
                case,
                false,
                AotSelectedEndV2TimingTerminal::Fault,
                Some(compile_ns),
                None,
                Some(super::elapsed_ns(setup_started)),
                Some(compiler_receipt.object_sha256),
                "timing.compile-v2.receipt-closure",
                error.to_string(),
            );
        }
    };
    let route_selected = supplemental.route_selected();
    if expected.policy != policy
        || expected.build.disposition != AotSelectedEndDisposition::Ready
        || expected.build.compiler.as_ref() != Some(&compiler_receipt)
        || expected.supplemental.as_ref() != Some(&supplemental)
        || expected.route_selected != route_selected
    {
        return v2_hot_setup_failure(
            policy,
            case,
            route_selected,
            AotSelectedEndV2TimingTerminal::Fault,
            Some(compile_ns),
            None,
            Some(super::elapsed_ns(setup_started)),
            Some(compiler_receipt.object_sha256),
            "timing.compile-v2.correctness-identity-changed",
            "timing compiler/schema/optimizer/report/module evidence differs from frozen correctness"
                .to_string(),
        );
    }
    let publish_started = Instant::now();
    let published = catch_unwind(AssertUnwindSafe(|| {
        publish_selected_end(compiled.into_compiled(), selected_end_publication_limits())
    }));
    let publish_ns = super::elapsed_ns(publish_started);
    let setup_ns = super::elapsed_ns(setup_started);
    let published = match published {
        Err(_) => {
            return v2_hot_setup_failure(
                policy,
                case,
                route_selected,
                AotSelectedEndV2TimingTerminal::Fault,
                Some(compile_ns),
                Some(publish_ns),
                Some(setup_ns),
                Some(compiler_receipt.object_sha256),
                "timing.publish-v2.panic",
                "V2 hot publication panicked".to_string(),
            );
        }
        Ok(Err(error)) => {
            return v2_hot_setup_failure(
                policy,
                case,
                route_selected,
                v2_disposition_terminal(publication_error_disposition(&error)),
                Some(compile_ns),
                Some(publish_ns),
                Some(setup_ns),
                Some(compiler_receipt.object_sha256),
                &publication_error_code(&error, "timing.publish-v2"),
                error.to_string(),
            );
        }
        Ok(Ok(published)) => published,
    };
    let publication = publication_evidence(&published);
    let artifact_binding =
        match v2_artifact_binding_sha256(policy, &compiler_receipt, &supplemental, &publication) {
            Ok(binding) => binding,
            Err(error) => {
                return v2_hot_setup_failure(
                    policy,
                    case,
                    route_selected,
                    AotSelectedEndV2TimingTerminal::Fault,
                    Some(compile_ns),
                    Some(publish_ns),
                    Some(setup_ns),
                    Some(compiler_receipt.object_sha256),
                    "timing.publish-v2.binding",
                    error.to_string(),
                );
            }
        };
    if expected.build.publication.as_ref() != Some(&publication)
        || expected.artifact_binding_sha256.as_ref() != Some(&artifact_binding)
    {
        return v2_hot_setup_failure(
            policy,
            case,
            route_selected,
            AotSelectedEndV2TimingTerminal::Fault,
            Some(compile_ns),
            Some(publish_ns),
            Some(setup_ns),
            Some(compiler_receipt.object_sha256),
            "timing.publish-v2.correctness-identity-changed",
            "timing published/module/report binding differs from frozen correctness".to_string(),
        );
    }
    LiveV2HotArtifact {
        setup: AotSelectedEndV2HotSetupReceipt {
            policy,
            case_id: case.id.clone(),
            route_selected,
            terminal: AotSelectedEndV2TimingTerminal::Executed,
            compile_ns: Some(compile_ns),
            publish_ns: Some(publish_ns),
            setup_ns: Some(setup_ns),
            compiler_object_sha256: Some(compiler_receipt.object_sha256),
            artifact_binding_sha256: Some(artifact_binding),
            reason_code: None,
            reason: None,
        },
        published: Some(published),
    }
}

#[allow(
    clippy::too_many_arguments,
    reason = "setup failures retain every completed timing boundary and identity explicitly"
)]
fn v2_hot_setup_failure(
    policy: AotSelectedEndV2Policy,
    case: &CaseSpec,
    route_selected: bool,
    terminal: AotSelectedEndV2TimingTerminal,
    compile_ns: Option<u64>,
    publish_ns: Option<u64>,
    setup_ns: Option<u64>,
    compiler_object_sha256: Option<String>,
    reason_code: &str,
    reason: String,
) -> LiveV2HotArtifact {
    LiveV2HotArtifact {
        setup: AotSelectedEndV2HotSetupReceipt {
            policy,
            case_id: case.id.clone(),
            route_selected,
            terminal,
            compile_ns,
            publish_ns,
            setup_ns,
            compiler_object_sha256,
            artifact_binding_sha256: None,
            reason_code: Some(reason_code.to_string()),
            reason: Some(reason),
        },
        published: None,
    }
}

const fn v2_disposition_terminal(
    disposition: AotSelectedEndDisposition,
) -> AotSelectedEndV2TimingTerminal {
    match disposition {
        AotSelectedEndDisposition::Ready => AotSelectedEndV2TimingTerminal::Executed,
        AotSelectedEndDisposition::Declined => AotSelectedEndV2TimingTerminal::Declined,
        AotSelectedEndDisposition::Fault => AotSelectedEndV2TimingTerminal::Fault,
    }
}

fn run_v2_hot_pair(
    entry: &AotSelectedEndV2ScheduledInput,
    repetition_index: usize,
    input: &AotSelectedEndSearchInput,
    expected_end: Option<usize>,
    automatic: &LiveV2HotArtifact,
    forced: &LiveV2HotArtifact,
) -> AotSelectedEndV2HotTimingPoint {
    let (automatic_observation, forced_observation) = match entry.first_policy {
        AotSelectedEndV2Policy::Automatic => (
            time_v2_hot(automatic, input, expected_end),
            time_v2_hot(forced, input, expected_end),
        ),
        AotSelectedEndV2Policy::ForceStructurallyEligible => {
            let forced_observation = time_v2_hot(forced, input, expected_end);
            let automatic_observation = time_v2_hot(automatic, input, expected_end);
            (automatic_observation, forced_observation)
        }
    };
    AotSelectedEndV2HotTimingPoint {
        input_index: entry.input_index,
        case_id: input.case_id.clone(),
        input_ordinal: input.input_ordinal,
        window_kind: input.window_kind,
        source_haystack_sha256: input.source_haystack_sha256.clone(),
        haystack_sha256: crate::sha256(&input.haystack),
        window_start: input.window_start,
        window_end: input.window_end,
        repetition_index,
        schedule_position: entry.schedule_position,
        expected_end,
        first_policy: entry.first_policy,
        automatic: automatic_observation,
        force_structurally_eligible: forced_observation,
    }
}

fn time_v2_hot(
    live: &LiveV2HotArtifact,
    input: &AotSelectedEndSearchInput,
    expected_end: Option<usize>,
) -> AotSelectedEndV2HotObservation {
    let Some(published) = &live.published else {
        return AotSelectedEndV2HotObservation {
            terminal: live.setup.terminal,
            search_ns: None,
            scan_attempted: false,
            actual_end: None,
            reason_code: live.setup.reason_code.clone(),
            reason: live.setup.reason.clone(),
        };
    };
    let window = SearchWindow::new(input.window_start, input.window_end);
    let started = Instant::now();
    let result = catch_unwind(AssertUnwindSafe(|| {
        published.search(black_box(input.haystack.as_slice()), black_box(window))
    }));
    let search_ns = super::elapsed_ns(started);
    match result {
        Err(_) => AotSelectedEndV2HotObservation {
            terminal: AotSelectedEndV2TimingTerminal::Fault,
            search_ns: Some(search_ns),
            scan_attempted: true,
            actual_end: None,
            reason_code: Some("timing.search-v2.panic".to_string()),
            reason: Some("published V2 SelectedEnd hot search panicked".to_string()),
        },
        Ok(Err(error)) => AotSelectedEndV2HotObservation {
            terminal: AotSelectedEndV2TimingTerminal::Fault,
            search_ns: Some(search_ns),
            scan_attempted: true,
            actual_end: None,
            reason_code: Some(call_error_code(&error)),
            reason: Some(error.to_string()),
        },
        Ok(Ok(actual_end)) if actual_end != expected_end => AotSelectedEndV2HotObservation {
            terminal: AotSelectedEndV2TimingTerminal::Mismatch,
            search_ns: Some(search_ns),
            scan_attempted: true,
            actual_end,
            reason_code: Some("timing.search-v2.semantic-mismatch".to_string()),
            reason: Some(format!(
                "published V2 SelectedEnd {actual_end:?} differs from frozen expected {expected_end:?}"
            )),
        },
        Ok(Ok(actual_end)) => AotSelectedEndV2HotObservation {
            terminal: AotSelectedEndV2TimingTerminal::Executed,
            search_ns: Some(search_ns),
            scan_attempted: true,
            actual_end,
            reason_code: None,
            reason: None,
        },
    }
}

fn v2_performance_coverage(
    correctness: &AotSelectedEndV2CorrectnessReport,
    setups: &[AotSelectedEndV2HotSetupReceipt],
    warmup: &[AotSelectedEndV2HotTimingPoint],
    measured: &[AotSelectedEndV2HotTimingPoint],
) -> AotSelectedEndV2PerformanceCoverage {
    let mut coverage = AotSelectedEndV2PerformanceCoverage {
        retained_case_patterns: correctness.coverage.case_patterns,
        structurally_ineligible_cases: correctness
            .coverage
            .by_eligibility
            .get(&AotSelectedEndV2Eligibility::StructurallyIneligible)
            .copied()
            .unwrap_or(0),
        compile_declined_cases: correctness
            .coverage
            .by_eligibility
            .get(&AotSelectedEndV2Eligibility::CompileDeclined)
            .copied()
            .unwrap_or(0),
        faulted_eligibility_cases: correctness
            .coverage
            .by_eligibility
            .get(&AotSelectedEndV2Eligibility::Fault)
            .copied()
            .unwrap_or(0),
        frozen_eligible_case_patterns: correctness.coverage.frozen_eligible_cases,
        frozen_eligible_search_windows: correctness.coverage.frozen_eligible_search_windows,
        setup_receipts: setups.len(),
        warmup_paired_points: warmup.len(),
        measured_paired_points: measured.len(),
        ..AotSelectedEndV2PerformanceCoverage::default()
    };
    for setup in setups {
        super::increment(
            coverage
                .setup_by_policy_terminal
                .entry(setup.policy)
                .or_default()
                .entry(setup.terminal)
                .or_default(),
        );
    }
    for point in warmup {
        for (policy, observation) in [
            (AotSelectedEndV2Policy::Automatic, &point.automatic),
            (
                AotSelectedEndV2Policy::ForceStructurallyEligible,
                &point.force_structurally_eligible,
            ),
        ] {
            super::increment(
                coverage
                    .warmup_by_policy_terminal
                    .entry(policy)
                    .or_default()
                    .entry(observation.terminal)
                    .or_default(),
            );
        }
    }
    for point in measured {
        for (policy, observation) in [
            (AotSelectedEndV2Policy::Automatic, &point.automatic),
            (
                AotSelectedEndV2Policy::ForceStructurallyEligible,
                &point.force_structurally_eligible,
            ),
        ] {
            super::increment(
                coverage
                    .measured_by_policy_terminal
                    .entry(policy)
                    .or_default()
                    .entry(observation.terminal)
                    .or_default(),
            );
        }
    }
    coverage
}

/// Validate the complete non-clock structure and terminal closure of a V2
/// timing report. Durations are opaque diagnostic observations.
#[allow(
    clippy::too_many_lines,
    reason = "the timing validator closes eligibility, schedule, setup identity, paired observations, coverage, and digest together"
)]
pub fn validate_aot_selected_end_v2_performance(
    authenticated: &AuthenticatedSuite,
    correctness: &AotSelectedEndV2CorrectnessReport,
    report: &AotSelectedEndV2PerformanceReport,
) -> Result<(), HoldoutError> {
    validate_aot_selected_end_v2_correctness(authenticated, correctness)?;
    enforce_aot_selected_end_v2_strict_gate(correctness)?;
    enforce_aot_selected_end_v2_timing_readiness(correctness)?;
    if report.schema != AOT_SELECTED_END_V2_PERFORMANCE_SCHEMA
        || report.suite_id != authenticated.manifest.suite_id
        || report.suite_sha256 != authenticated.suite_sha256
        || report.json_schema_sha256 != authenticated.json_schema_sha256
        || report.expanded_inputs_sha256 != authenticated.expanded_inputs_sha256
        || report.window_matrix_sha256 != correctness.window_matrix_sha256
        || report.correctness_receipts_sha256 != correctness.receipts_sha256
        || report.correctness_provenance_sha256 != correctness.provenance_sha256
        || report.frozen_eligibility_sha256 != correctness.eligibility_sha256
        || report.frozen_eligible_case_ids != correctness.frozen_eligible_case_ids
        || report.target_arch != std::env::consts::ARCH
        || report.target_os != std::env::consts::OS
        || report.target_pointer_width != usize::BITS
        || report.host != correctness.host
        || report.provenance != correctness.provenance
        || report.policy != authenticated.manifest.timing
        || report.limit_policy != correctness.limit_policy
        || report.normative
        || report.planner_feedback_permitted
        || report.eligibility_identity != V2_ELIGIBILITY_IDENTITY
        || report.hot_measurement_scope != V2_HOT_MEASUREMENT_SCOPE
        || report.pairing_schedule != V2_PAIRING_DESCRIPTION
        || report.readiness_floor != v2_readiness_description(correctness)
    {
        return Err(HoldoutError::new(
            "V2 timing report authentication binding is invalid",
        ));
    }
    let expected_budget = v2_observation_budget(
        correctness.coverage.frozen_eligible_search_windows,
        correctness.coverage.frozen_eligible_cases,
        report.policy,
    )?;
    if report.observation_budget != expected_budget {
        return Err(HoldoutError::new(
            "V2 timing observation budget does not recompute",
        ));
    }
    let inputs = aot_search_inputs(authenticated)?;
    let eligible_case_ids = correctness
        .frozen_eligible_case_ids
        .iter()
        .map(String::as_str)
        .collect::<BTreeSet<_>>();
    let eligible_input_indices = inputs
        .iter()
        .enumerate()
        .filter(|(_, input)| eligible_case_ids.contains(input.case_id.as_str()))
        .map(|(index, _)| index)
        .collect::<Vec<_>>();
    let expected_ends = v2_expected_ends(correctness, &inputs, &eligible_input_indices)?;
    let expected_schedule = build_v2_schedule(
        authenticated,
        correctness,
        &inputs,
        &eligible_input_indices,
        report.policy,
    )?;
    if report.schedule != expected_schedule {
        return Err(HoldoutError::new(
            "V2 timing schedule does not deterministically recompute",
        ));
    }
    validate_v2_setups(authenticated, correctness, &report.hot_setups)?;
    let setups = report
        .hot_setups
        .iter()
        .map(|setup| ((setup.case_id.as_str(), setup.policy), setup))
        .collect::<BTreeMap<_, _>>();
    validate_v2_timing_points(
        &inputs,
        &expected_ends,
        &setups,
        &report.schedule.warmup,
        &report.warmup_points,
    )?;
    validate_v2_timing_points(
        &inputs,
        &expected_ends,
        &setups,
        &report.schedule.measured,
        &report.measured_points,
    )?;
    let coverage = v2_performance_coverage(
        correctness,
        &report.hot_setups,
        &report.warmup_points,
        &report.measured_points,
    );
    if report.coverage != coverage {
        return Err(HoldoutError::new("V2 timing coverage does not recompute"));
    }
    let timing_bytes = serde_json::to_vec(&(
        &correctness.limit_policy,
        &correctness.eligibility_sha256,
        &report.observation_budget,
        &report.schedule,
        &report.hot_setups,
        &report.warmup_points,
        &report.measured_points,
    ))
    .map_err(|error| HoldoutError::new(format!("recompute V2 timing receipts: {error}")))?;
    if report.timing_receipts_sha256 != crate::sha256(&timing_bytes) {
        return Err(HoldoutError::new(
            "V2 timing receipt digest does not recompute",
        ));
    }
    Ok(())
}

fn validate_v2_setups(
    authenticated: &AuthenticatedSuite,
    correctness: &AotSelectedEndV2CorrectnessReport,
    setups: &[AotSelectedEndV2HotSetupReceipt],
) -> Result<(), HoldoutError> {
    let expected_count = correctness
        .coverage
        .frozen_eligible_cases
        .checked_mul(AotSelectedEndV2Policy::ALL.len())
        .ok_or_else(|| HoldoutError::new("V2 setup validation count overflow"))?;
    if setups.len() != expected_count {
        return Err(HoldoutError::new("V2 hot setup matrix has the wrong size"));
    }
    let eligible = correctness
        .frozen_eligible_case_ids
        .iter()
        .map(String::as_str)
        .collect::<BTreeSet<_>>();
    let mut setup_index = 0_usize;
    for (spec, case) in authenticated.manifest.cases.iter().zip(&correctness.cases) {
        if !eligible.contains(spec.id.as_str()) {
            continue;
        }
        for policy in AotSelectedEndV2Policy::ALL {
            let setup = setups
                .get(setup_index)
                .ok_or_else(|| HoldoutError::new("V2 setup matrix ended early"))?;
            let expected = case.artifact(policy);
            if setup.policy != policy || setup.case_id != spec.id {
                return Err(HoldoutError::new(format!(
                    "V2 setup identity is invalid for {}:{policy:?}",
                    spec.id
                )));
            }
            validate_v2_setup(expected, setup)?;
            setup_index = setup_index
                .checked_add(1)
                .ok_or_else(|| HoldoutError::new("V2 setup index overflow"))?;
        }
    }
    Ok(())
}

fn validate_v2_setup(
    expected: &AotSelectedEndV2PolicyArtifactReceipt,
    setup: &AotSelectedEndV2HotSetupReceipt,
) -> Result<(), HoldoutError> {
    if setup.policy != expected.policy || setup.case_id != expected.build.case_id {
        return Err(HoldoutError::new(format!(
            "V2 setup does not match its frozen policy artifact for {}:{:?}",
            setup.case_id, setup.policy
        )));
    }
    if let Some(object) = &setup.compiler_object_sha256
        && expected
            .build
            .compiler
            .as_ref()
            .map(|compiler| &compiler.object_sha256)
            != Some(object)
    {
        return Err(HoldoutError::new(format!(
            "V2 setup compiler identity changed for {}:{:?}",
            setup.case_id, setup.policy
        )));
    }
    match setup.terminal {
        AotSelectedEndV2TimingTerminal::Executed => {
            if setup.route_selected != expected.route_selected
                || setup.compile_ns.is_none()
                || setup.publish_ns.is_none()
                || setup.setup_ns.is_none()
                || setup.compiler_object_sha256.is_none()
                || setup.artifact_binding_sha256 != expected.artifact_binding_sha256
                || setup.reason_code.is_some()
                || setup.reason.is_some()
            {
                return Err(HoldoutError::new(format!(
                    "executed V2 setup has invalid route/clock/identity closure for {}:{:?}",
                    setup.case_id, setup.policy
                )));
            }
        }
        AotSelectedEndV2TimingTerminal::Declined | AotSelectedEndV2TimingTerminal::Fault => {
            if setup.compile_ns.is_none()
                || setup.setup_ns.is_none()
                || setup.artifact_binding_sha256.is_some()
                || setup.reason_code.is_none()
                || setup.reason.is_none()
                || (setup.compiler_object_sha256.is_none()
                    && (setup.route_selected || setup.publish_ns.is_some()))
            {
                return Err(HoldoutError::new(format!(
                    "terminal V2 setup has invalid observed-stage/clock/reason closure for {}:{:?}",
                    setup.case_id, setup.policy
                )));
            }
        }
        AotSelectedEndV2TimingTerminal::Mismatch => {
            return Err(HoldoutError::new(
                "V2 setup cannot have a semantic-mismatch terminal",
            ));
        }
    }
    if let Some(setup_ns) = setup.setup_ns
        && (setup.compile_ns.is_some_and(|clock| clock > setup_ns)
            || setup.publish_ns.is_some_and(|clock| clock > setup_ns))
    {
        return Err(HoldoutError::new(
            "V2 setup component clock exceeds its enclosing setup clock",
        ));
    }
    Ok(())
}

fn validate_v2_timing_points(
    inputs: &[AotSelectedEndSearchInput],
    expected_ends: &BTreeMap<usize, Option<usize>>,
    setups: &BTreeMap<(&str, AotSelectedEndV2Policy), &AotSelectedEndV2HotSetupReceipt>,
    sweeps: &[AotSelectedEndV2ScheduledSweep],
    points: &[AotSelectedEndV2HotTimingPoint],
) -> Result<(), HoldoutError> {
    let expected_points = sweeps
        .iter()
        .try_fold(0_usize, |total, sweep| {
            total.checked_add(sweep.entries.len())
        })
        .ok_or_else(|| HoldoutError::new("V2 timing point validation count overflow"))?;
    if points.len() != expected_points {
        return Err(HoldoutError::new(
            "V2 timing point matrix has the wrong size",
        ));
    }
    let mut point_index = 0_usize;
    for sweep in sweeps {
        for entry in &sweep.entries {
            let input = v2_scheduled_input(inputs, entry)?;
            let point = points
                .get(point_index)
                .ok_or_else(|| HoldoutError::new("V2 timing point matrix ended early"))?;
            let expected_end = *expected_ends
                .get(&entry.input_index)
                .ok_or_else(|| HoldoutError::new("V2 point omitted frozen expected end"))?;
            if point.input_index != entry.input_index
                || point.case_id != input.case_id
                || point.input_ordinal != input.input_ordinal
                || point.window_kind != input.window_kind
                || point.source_haystack_sha256 != input.source_haystack_sha256
                || point.haystack_sha256 != crate::sha256(&input.haystack)
                || point.window_start != input.window_start
                || point.window_end != input.window_end
                || point.repetition_index != sweep.repetition_index
                || point.schedule_position != entry.schedule_position
                || point.expected_end != expected_end
                || point.first_policy != entry.first_policy
            {
                return Err(HoldoutError::new(format!(
                    "V2 timing point identity is invalid for {}:{}:{:?}",
                    input.case_id, input.input_ordinal, input.window_kind
                )));
            }
            for (policy, observation) in [
                (AotSelectedEndV2Policy::Automatic, &point.automatic),
                (
                    AotSelectedEndV2Policy::ForceStructurallyEligible,
                    &point.force_structurally_eligible,
                ),
            ] {
                let setup = setups
                    .get(&(input.case_id.as_str(), policy))
                    .ok_or_else(|| HoldoutError::new("V2 timing point omitted its setup"))?;
                validate_v2_hot_observation(expected_end, setup, observation)?;
            }
            point_index = point_index
                .checked_add(1)
                .ok_or_else(|| HoldoutError::new("V2 timing point index overflow"))?;
        }
    }
    Ok(())
}

fn validate_v2_hot_observation(
    expected_end: Option<usize>,
    setup: &AotSelectedEndV2HotSetupReceipt,
    observation: &AotSelectedEndV2HotObservation,
) -> Result<(), HoldoutError> {
    if setup.terminal != AotSelectedEndV2TimingTerminal::Executed {
        if observation.terminal != setup.terminal
            || observation.search_ns.is_some()
            || observation.scan_attempted
            || observation.actual_end.is_some()
            || observation.reason_code != setup.reason_code
            || observation.reason != setup.reason
        {
            return Err(HoldoutError::new(
                "V2 observation does not retain its unavailable setup terminal",
            ));
        }
        return Ok(());
    }
    match observation.terminal {
        AotSelectedEndV2TimingTerminal::Executed => {
            if observation.search_ns.is_none()
                || !observation.scan_attempted
                || observation.actual_end != expected_end
                || observation.reason_code.is_some()
                || observation.reason.is_some()
            {
                return Err(HoldoutError::new(
                    "executed V2 hot observation has invalid closure",
                ));
            }
        }
        AotSelectedEndV2TimingTerminal::Mismatch => {
            if observation.search_ns.is_none()
                || !observation.scan_attempted
                || observation.actual_end == expected_end
                || observation.reason_code.is_none()
                || observation.reason.is_none()
            {
                return Err(HoldoutError::new(
                    "mismatched V2 hot observation has invalid closure",
                ));
            }
        }
        AotSelectedEndV2TimingTerminal::Fault => {
            if observation.search_ns.is_none()
                || !observation.scan_attempted
                || observation.actual_end.is_some()
                || observation.reason_code.is_none()
                || observation.reason.is_none()
            {
                return Err(HoldoutError::new(
                    "faulted V2 hot observation has invalid closure",
                ));
            }
        }
        AotSelectedEndV2TimingTerminal::Declined => {
            return Err(HoldoutError::new(
                "ready V2 hot setup cannot decline during a direct call",
            ));
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use fre_aot_regex::{CpuFeature, FeatureSet};

    use super::*;
    use crate::{
        DimensionDeclaration, ExplicitInput, GeneratorSpec, OracleDeclaration, SuiteManifest,
        expand_manifest,
    };

    fn policy_fixture(pattern: &str) -> AuthenticatedSuite {
        let manifest = SuiteManifest {
            schema: "fre.holdout.suite.v1".to_string(),
            suite_id: "v2-policy-fixture".to_string(),
            freeze_date: "2026-08-21".to_string(),
            oracle: OracleDeclaration {
                implementation: "rust-regex".to_string(),
                version: "1.12.4".to_string(),
                api: "bytes".to_string(),
                unicode: false,
            },
            timing: TimingPolicy {
                warmup_iterations: 4,
                measured_iterations: 4,
            },
            dimensions: Vec::<DimensionDeclaration>::new(),
            cases: vec![CaseSpec {
                id: "policy-case".to_string(),
                family: "v2-test".to_string(),
                labels: vec!["structural".to_string()],
                pattern: pattern.to_string(),
                generator: GeneratorSpec::Explicit {
                    inputs: vec![
                        ExplicitInput {
                            hex: "787873616d776973657979".to_string(),
                            intent: "positive".to_string(),
                        },
                        ExplicitInput {
                            hex: "78787878".to_string(),
                            intent: "negative".to_string(),
                        },
                    ],
                },
            }],
        };
        let inputs = expand_manifest(&manifest).expect("expand V2 fixture");
        AuthenticatedSuite {
            manifest,
            inputs,
            suite_sha256: "fixture-suite".to_string(),
            json_schema_sha256: "fixture-schema".to_string(),
            expanded_inputs_sha256: "fixture-inputs".to_string(),
        }
    }

    #[test]
    #[allow(
        clippy::too_many_lines,
        reason = "one focused test closes both policy receipts and all three correctness paths across both window kinds"
    )]
    fn both_v2_policies_have_three_way_full_and_bounded_correctness() {
        let authenticated = policy_fixture("samwise|samw|frodo|pippin");
        let (host, target) = resolve_host_target();
        let Some(target) = target else {
            return;
        };
        let case = &authenticated.manifest.cases[0];
        let inputs = aot_search_inputs(&authenticated).expect("V2 fixture windows");
        let automatic = build_v2_policy_artifact(
            case,
            authenticated.inputs.len(),
            inputs.len(),
            AotSelectedEndV2Policy::Automatic,
            Some(target),
            &host,
        );
        let forced = build_v2_policy_artifact(
            case,
            authenticated.inputs.len(),
            inputs.len(),
            AotSelectedEndV2Policy::ForceStructurallyEligible,
            Some(target),
            &host,
        );
        assert_eq!(
            automatic.receipt.build.disposition,
            AotSelectedEndDisposition::Ready
        );
        assert_eq!(
            forced.receipt.build.disposition,
            AotSelectedEndDisposition::Ready
        );
        let automatic_supplemental = automatic
            .receipt
            .supplemental
            .as_ref()
            .expect("Automatic supplemental receipt");
        let forced_supplemental = forced
            .receipt
            .supplemental
            .as_ref()
            .expect("forced supplemental receipt");
        assert_eq!(
            automatic_supplemental.requested_policy,
            AotSelectedEndV2Policy::Automatic
        );
        assert_eq!(
            automatic_supplemental.stable_v1_teddy_report_present,
            automatic.receipt.route_selected
        );
        assert!(!automatic_supplemental.module_v2_teddy_report_present);
        assert_eq!(
            forced_supplemental.requested_policy,
            AotSelectedEndV2Policy::ForceStructurallyEligible
        );
        assert!(!forced_supplemental.stable_v1_teddy_report_present);
        assert!(!forced_supplemental.module_v1_teddy_report_present);
        assert_eq!(
            forced_supplemental.module_v2_teddy_report_present,
            forced.receipt.route_selected
        );
        let teddy_capable = target
            .features
            .contains(FeatureSet::of(CpuFeature::X86Avx2))
            || target
                .features
                .contains(FeatureSet::of(CpuFeature::Aarch64Asimd));
        if teddy_capable {
            assert!(forced.receipt.route_selected);
            assert_eq!(
                forced_eligibility(&forced.receipt),
                AotSelectedEndV2Eligibility::StructurallyEligible
            );
            let route = forced_supplemental
                .route
                .as_ref()
                .expect("forced structural route");
            assert_eq!(route.selection_basis, "ForcedStructuralEligibility");
            assert!(route.performance_admission_bypassed);
            assert_eq!(
                route.program_artifact_identity_sha256,
                route.report_artifact_identity_sha256
            );
        }

        let oracle = independent_oracle(&case.pattern).expect("V2 fixture oracle");
        let mut kinds = BTreeSet::new();
        for input in &inputs {
            kinds.insert(input.window_kind);
            let (oracle_kind, oracle_end) = independent_end(&oracle, input);
            for built in [&automatic, &forced] {
                let comparison = compare_input(
                    input,
                    oracle_kind,
                    oracle_end,
                    &built.receipt.build,
                    built.portable.as_ref(),
                    built.published.as_ref(),
                );
                assert_eq!(comparison.status, AotSelectedEndComparisonStatus::Pass);
                assert!(comparison.portable_call_attempted);
                assert!(comparison.native_call_attempted);
                assert_eq!(comparison.actual_end, comparison.expected_end);
                assert_eq!(comparison.expected_end, comparison.independent_end);
            }
        }
        assert_eq!(
            kinds,
            BTreeSet::from([
                AotSelectedEndWindowKind::Full,
                AotSelectedEndWindowKind::MidscanNonzeroBounded,
            ])
        );
    }

    #[test]
    fn forced_incumbent_fallback_is_never_structurally_eligible() {
        let authenticated = policy_fixture("needle");
        let (host, target) = resolve_host_target();
        let Some(target) = target else {
            return;
        };
        let case = &authenticated.manifest.cases[0];
        let mut forced = build_v2_policy_artifact(
            case,
            authenticated.inputs.len(),
            authenticated.inputs.len() * 2,
            AotSelectedEndV2Policy::ForceStructurallyEligible,
            Some(target),
            &host,
        )
        .receipt;
        assert_eq!(forced.build.disposition, AotSelectedEndDisposition::Ready);
        assert!(!forced.route_selected);
        assert!(
            forced
                .supplemental
                .as_ref()
                .is_some_and(|supplemental| supplemental.route.is_none())
        );
        assert_eq!(
            forced_eligibility(&forced),
            AotSelectedEndV2Eligibility::StructurallyIneligible
        );
        // A redundant label cannot create eligibility: only the authenticated
        // forced supplemental report is authoritative.
        forced.route_selected = true;
        assert_eq!(
            forced_eligibility(&forced),
            AotSelectedEndV2Eligibility::StructurallyIneligible
        );
    }

    fn schedule_inputs(count: usize) -> Vec<AotSelectedEndSearchInput> {
        (0..count)
            .map(|index| AotSelectedEndSearchInput {
                source_index: index / 2,
                case_id: format!("case-{}", index / 2),
                family: "schedule".to_string(),
                labels: Vec::new(),
                pattern: "x".to_string(),
                input_ordinal: index / 2,
                declared_intent: "schedule".to_string(),
                window_kind: if index % 2 == 0 {
                    AotSelectedEndWindowKind::Full
                } else {
                    AotSelectedEndWindowKind::MidscanNonzeroBounded
                },
                source_haystack_sha256: format!("source-{index}"),
                haystack: vec![u8::try_from(index).unwrap_or(u8::MAX)],
                window_start: usize::from(index % 2 != 0),
                window_end: 1,
            })
            .collect()
    }

    #[test]
    fn v2_hot_schedule_is_deterministic_reversed_and_policy_counterbalanced() {
        let inputs = schedule_inputs(8);
        let eligible = vec![0, 1, 4, 5, 6, 7];
        let first = v2_scheduled_sweeps(
            &inputs,
            &eligible,
            AotSelectedEndV2SchedulePhase::Measured,
            4,
            0x1234_5678_9abc_def0,
        )
        .expect("first V2 schedule");
        let second = v2_scheduled_sweeps(
            &inputs,
            &eligible,
            AotSelectedEndV2SchedulePhase::Measured,
            4,
            0x1234_5678_9abc_def0,
        )
        .expect("second V2 schedule");
        assert_eq!(first, second);
        for pair in first.chunks_exact(2) {
            let even = pair[0]
                .entries
                .iter()
                .map(|entry| entry.input_index)
                .collect::<Vec<_>>();
            let odd = pair[1]
                .entries
                .iter()
                .map(|entry| entry.input_index)
                .collect::<Vec<_>>();
            assert_eq!(even.iter().rev().copied().collect::<Vec<_>>(), odd);
            assert_eq!(
                even.iter().copied().collect::<BTreeSet<_>>(),
                eligible.iter().copied().collect()
            );
            for &input_index in &eligible {
                let even_policy = pair[0]
                    .entries
                    .iter()
                    .find(|entry| entry.input_index == input_index)
                    .expect("even input")
                    .first_policy;
                let odd_policy = pair[1]
                    .entries
                    .iter()
                    .find(|entry| entry.input_index == input_index)
                    .expect("odd input")
                    .first_policy;
                assert_ne!(even_policy, odd_policy);
            }
        }
    }

    #[test]
    fn v2_observation_budget_fails_closed_before_campaign_allocation() {
        let ordinary = v2_observation_budget(
            338,
            19,
            TimingPolicy {
                warmup_iterations: 3,
                measured_iterations: 9,
            },
        )
        .expect("ordinary frozen V2 budget");
        assert_eq!(ordinary.planned_total_timing_observations, 8_150);
        assert!(
            v2_observation_budget(
                MAX_V2_TIMING_OBSERVATIONS,
                1,
                TimingPolicy {
                    warmup_iterations: 1,
                    measured_iterations: 1,
                },
            )
            .is_err()
        );
    }

    fn eligible_forced_timing_fixture() -> Option<(CaseSpec, AotSelectedEndV2PolicyArtifactReceipt)>
    {
        let authenticated = policy_fixture("samwise|samw|frodo|pippin");
        let (host, target) = resolve_host_target();
        let target = target?;
        let case = authenticated.manifest.cases[0].clone();
        let inputs = aot_search_inputs(&authenticated).expect("V2 timing fixture windows");
        let expected = build_v2_policy_artifact(
            &case,
            authenticated.inputs.len(),
            inputs.len(),
            AotSelectedEndV2Policy::ForceStructurallyEligible,
            Some(target),
            &host,
        )
        .receipt;
        if !expected.route_selected {
            return None;
        }
        assert_eq!(expected.build.disposition, AotSelectedEndDisposition::Ready);
        assert!(expected.artifact_binding_sha256.is_some());
        Some((case, expected))
    }

    #[test]
    fn terminal_v2_setup_clocks_fail_closed_under_tampering() {
        let Some((case, expected)) = eligible_forced_timing_fixture() else {
            return;
        };
        let generated = v2_hot_setup_failure(
            AotSelectedEndV2Policy::ForceStructurallyEligible,
            &case,
            false,
            AotSelectedEndV2TimingTerminal::Declined,
            Some(5),
            None,
            Some(8),
            None,
            "timing.compile-v2.declined.test",
            "synthetic pre-route decline".to_string(),
        );
        assert!(generated.published.is_none());
        validate_v2_setup(&expected, &generated.setup)
            .expect("pre-route decline remains a valid diagnostic setup");

        let mut missing_compile_clock = generated.setup.clone();
        missing_compile_clock.compile_ns = None;
        assert!(validate_v2_setup(&expected, &missing_compile_clock).is_err());

        let mut compile_exceeds_setup = generated.setup.clone();
        compile_exceeds_setup.compile_ns = Some(9);
        assert!(validate_v2_setup(&expected, &compile_exceeds_setup).is_err());

        let object_sha256 = expected
            .build
            .compiler
            .as_ref()
            .expect("eligible fixture compiler evidence")
            .object_sha256
            .clone();
        let generated_publication_fault = v2_hot_setup_failure(
            AotSelectedEndV2Policy::ForceStructurallyEligible,
            &case,
            true,
            AotSelectedEndV2TimingTerminal::Fault,
            Some(4),
            Some(7),
            Some(8),
            Some(object_sha256),
            "timing.publish-v2.fault.test",
            "synthetic publication fault".to_string(),
        );
        validate_v2_setup(&expected, &generated_publication_fault.setup)
            .expect("post-route publication fault remains valid");
        let mut publish_exceeds_setup = generated_publication_fault.setup;
        publish_exceeds_setup.publish_ns = Some(9);
        assert!(validate_v2_setup(&expected, &publish_exceeds_setup).is_err());
    }

    #[test]
    fn forced_eligible_setup_retains_terminals_but_executed_route_mismatch_fails() {
        let Some((case, expected)) = eligible_forced_timing_fixture() else {
            return;
        };
        let object_sha256 = expected
            .build
            .compiler
            .as_ref()
            .expect("eligible fixture compiler evidence")
            .object_sha256
            .clone();
        for terminal in [
            AotSelectedEndV2TimingTerminal::Declined,
            AotSelectedEndV2TimingTerminal::Fault,
        ] {
            let pre_route = v2_hot_setup_failure(
                AotSelectedEndV2Policy::ForceStructurallyEligible,
                &case,
                false,
                terminal,
                Some(3),
                None,
                Some(5),
                None,
                "timing.compile-v2.pre-route.test",
                "synthetic pre-route terminal".to_string(),
            );
            assert!(pre_route.published.is_none());
            validate_v2_setup(&expected, &pre_route.setup)
                .expect("a forced-eligible case retains its pre-route terminal");
        }

        let supplemental_fault = v2_hot_setup_failure(
            AotSelectedEndV2Policy::ForceStructurallyEligible,
            &case,
            false,
            AotSelectedEndV2TimingTerminal::Fault,
            Some(3),
            None,
            Some(5),
            Some(object_sha256.clone()),
            "timing.compile-v2.receipt-closure",
            "synthetic supplemental receipt fault".to_string(),
        );
        validate_v2_setup(&expected, &supplemental_fault.setup)
            .expect("supplemental fault retains its observed absent route");

        let publication_decline = v2_hot_setup_failure(
            AotSelectedEndV2Policy::ForceStructurallyEligible,
            &case,
            true,
            AotSelectedEndV2TimingTerminal::Declined,
            Some(3),
            Some(4),
            Some(6),
            Some(object_sha256.clone()),
            "timing.publish-v2.declined.test",
            "synthetic publication decline".to_string(),
        );
        validate_v2_setup(&expected, &publication_decline.setup)
            .expect("publication decline retains the observed route");
        let mut terminal_route_observation = publication_decline.setup;
        terminal_route_observation.route_selected = false;
        validate_v2_setup(&expected, &terminal_route_observation)
            .expect("a terminal route observation is diagnostic, not frozen eligibility");

        let mut executed = AotSelectedEndV2HotSetupReceipt {
            policy: AotSelectedEndV2Policy::ForceStructurallyEligible,
            case_id: case.id,
            route_selected: true,
            terminal: AotSelectedEndV2TimingTerminal::Executed,
            compile_ns: Some(3),
            publish_ns: Some(4),
            setup_ns: Some(6),
            compiler_object_sha256: Some(object_sha256),
            artifact_binding_sha256: expected.artifact_binding_sha256.clone(),
            reason_code: None,
            reason: None,
        };
        validate_v2_setup(&expected, &executed).expect("executed fixture closes exactly");
        executed.route_selected = false;
        assert!(validate_v2_setup(&expected, &executed).is_err());
    }

    #[test]
    fn empty_frozen_set_is_inadmissible_for_timing() {
        let authenticated = policy_fixture("needle");
        let report = run_aot_selected_end_v2_correctness(&authenticated)
            .expect("clock-free ineligible V2 fixture");
        assert_eq!(report.coverage.frozen_eligible_cases, 0);
        assert!(report.frozen_eligible_case_ids.is_empty());
        let error = enforce_aot_selected_end_v2_timing_readiness(&report)
            .expect_err("an empty V2 frozen set must reject timing");
        assert!(
            error
                .to_string()
                .contains("at least one structurally eligible")
        );
    }
}
