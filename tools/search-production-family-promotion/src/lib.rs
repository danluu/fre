//! Fail-closed, review-rooted Search AOT production-family renderer.
//!
//! The qualification analyzer is deliberately not its own deployment
//! authority.  A caller must provide an independently reviewed authorization
//! file and its exact SHA-256 on the command line.  That authorization pins the
//! campaign contract, analyzer source, runner source, exact analyzer output,
//! every production row field, and the expected identities.  This tool
//! reconstructs those values before it emits a reviewable source atom; it
//! never edits the runtime source tree.

#![forbid(unsafe_code)]
#![recursion_limit = "256"]

use std::collections::{BTreeMap, BTreeSet};
use std::ffi::{OsStr, OsString};
use std::fmt;
use std::fs::{self, File, OpenOptions};
use std::io::{Read, Write};
#[cfg(unix)]
use std::os::unix::fs::{MetadataExt, OpenOptionsExt, PermissionsExt};
use std::path::{Path, PathBuf};

use fre_aot_compiler::{
    AOT_LINUX_SEARCH_COMPILER_VERSION_V1, AOT_SEARCH_COMPILER_VERSION_V1,
    LinuxAarch64ExactSearchManifestV1, LinuxAarch64SearchCompilePolicyV1,
    MacosAarch64ExactSearchManifestV1, SearchCompilePolicyV1,
};
use fre_aot_search_contract::{
    SEARCH_ARCHITECTURE_AARCH64_V1, SEARCH_CALL_ABI_SCHEMA_V1,
    SEARCH_EXPORTED_SYMBOL_INFO_ELF_FUNCTION_V1, SEARCH_EXPORTED_SYMBOL_N_TYPE_V1,
    SEARCH_EXPORTED_SYMBOL_SCHEMA_VERSION_V1, SEARCH_METADATA_VERSION_V1, SEARCH_PLATFORM_LINUX_V1,
    SEARCH_PLATFORM_MACOS_V1, SEARCH_POINTER_WIDTH_V1, SEARCH_REQUIRED_ASIMD_FEATURES_V1,
    SEARCH_SPAN_OUTPUT_KIND_V1, SEARCH_STATUS_BITS_V1, SEARCH_TARGET_ABI_AAPCS64_V1,
};
use fre_kernel_ir::Span;
use serde::{Deserialize, Serialize};
use serde_json::{Map, Value, json};
use sha2::{Digest, Sha256};

const AUTHORIZATION_SCHEMA: &str = "fre.aot.search-production-family-promotion-authorization.v1";
const PRIVATE_AUTHORIZATION_SCHEMA: &str =
    "fre.aot.search-tag30-qualification-discovery-authorization.v1";
const RECEIPT_SCHEMA: &str = "fre.aot.search-production-family-promotion-receipt.v1";
const PRIVATE_RECEIPT_SCHEMA: &str = "fre.aot.search-private-family-discovery-receipt.v1";
const COMMIT_SCHEMA: &str = "fre.aot.search-production-family-promotion-commit.v1";
const PRIVATE_COMMIT_SCHEMA: &str = "fre.aot.search-private-family-discovery-commit.v1";
const BUILD_RECEIPT_SCHEMA: &str = "fre.aot.search-tag30-qualification-runner-build-receipt.v1";
const STATIC_ABI_SCHEMA: &str = "fre-aot-static-search-span-v1";
const OUTPUT_TYPE: &str = "Span";
const LINK_INTERFACE_SCHEMA: &str = "fre.aot.search-span-family-qualification-final-image-glue.v1";
const TAG30_AOT_MAGIC_HEX: &str = "465245413634001e";
const COMPILER_PROFILE: &str = "high-fuel-v1";
const EVIDENCE_DOMAIN: &[u8] = b"FRE-SEARCH-TAG30-QUALIFICATION-EVIDENCE\0\x01";
const MAX_INPUT_BYTES: u64 = 16 << 20;
const OUTPUT_RUST: &str = "production-families.rs";
const PRIVATE_OUTPUT_RUST: &str = "private_rows.rs";
const OUTPUT_RECEIPT: &str = "authorization-receipt.json";
const OUTPUT_SHA256SUMS: &str = "SHA256SUMS";
const OUTPUT_COMMITTED: &str = "COMMITTED";

#[derive(Debug, Clone, Eq, PartialEq)]
pub struct PromotionError(String);

impl PromotionError {
    fn new(message: impl Into<String>) -> Self {
        Self(message.into())
    }
}

impl fmt::Display for PromotionError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(&self.0)
    }
}

impl std::error::Error for PromotionError {}

type Result<T> = std::result::Result<T, PromotionError>;

fn fail<T>(message: impl Into<String>) -> Result<T> {
    Err(PromotionError::new(message))
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
struct Authorization {
    schema: String,
    decision: AuthorizationDecision,
    inputs: AuthorizationInputs,
    family: AuthorizedFamily,
    identities: AuthorizedIdentities,
    qualification: AuthorizedQualification,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
struct PrivateAuthorization {
    schema: String,
    payload_sha256: String,
    payload: PrivateAuthorizationPayload,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct PrivateAuthorizationPayload {
    contract_schema: String,
    campaign_contract_sha256: String,
    analyzer_source_sha256: String,
    prepared_inputs_sha256: String,
    object_candidate_manifest_schema: String,
    object_candidate_manifest_sha256: String,
    object_candidate_manifest_payload_sha256: String,
    literal_dispositions_schema: String,
    literal_dispositions_sha256: String,
    literal_dispositions_payload_sha256: String,
    prepare_source_sha256: String,
    discovery_runner_revision: String,
    discovery_runner_source_sha256: String,
    discovery_source_archive_sha256: String,
    discovery_identity_sha256: String,
    discovery_private_family_source_sha256: String,
    family_common: PrivateFamilyCommon,
    decision: PrivateAuthorizationDecision,
    qualification: AuthorizedQualification,
    targets: BTreeMap<String, PrivateAuthorizedTarget>,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct PrivateAuthorizationDecision {
    private_projection: bool,
    production_projection: bool,
    pre_result_intent: bool,
    analyzer_not_deployment_authority: bool,
    targets_one_class: bool,
    rebar_permitted: bool,
    result_derived_exclusions: bool,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct PrivateFamilyCommon {
    backend: PrivateBackend,
    compiler: PrivateCompiler,
    wire: PrivateWire,
    envelope: PrivateEnvelope,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct PrivateBackend {
    name: String,
    tag: u16,
    version: String,
    candidate_policy: u16,
    llvm: bool,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct PrivateCompiler {
    identity: String,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct PrivateWire {
    aot_magic_hex: String,
    static_abi: String,
    output: String,
    link_interface_schema: String,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct PrivateEnvelope {
    family_selector: u16,
    minimum_literal_bytes: u32,
    maximum_literal_bytes: u32,
    minimum_window_bytes: u32,
    portable_prefix_candidate_starts: u32,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct PrivateAuthorizedTarget {
    host_id: String,
    target_os: String,
    target_arch: String,
    manifest_identity: String,
    discovery_build_receipt_schema: String,
    discovery_build_receipt_sha256: String,
    family_tuple: AuthorizedFamilyTuple,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
struct AuthorizationDecision {
    production_source_projection_authorized: bool,
    analyzer_is_not_deployment_authority: bool,
    targets_reviewed_as_one_class: bool,
    rebar_accepted_as_input: bool,
    result_derived_exclusions_authorized: bool,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
struct AuthorizationInputs {
    contract_schema: String,
    contract_sha256: String,
    analysis_schema: String,
    analysis_sha256: String,
    analyzer_source_sha256: String,
    runner_source_sha256: String,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct AuthorizedFamily {
    selector: u16,
    backend_tag: u16,
    backend_name: String,
    backend_version: String,
    candidate_policy: u16,
    aot_magic_hex: String,
    compiler_profile: String,
    minimum_literal_bytes: u32,
    maximum_literal_bytes: u32,
    minimum_window_bytes: u32,
    portable_prefix_candidate_starts: u32,
    wire: AuthorizedWireProfile,
    targets: Vec<AuthorizedTarget>,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct AuthorizedWireProfile {
    compiler_version: u16,
    metadata_version: u16,
    backend_version: u16,
    call_abi_schema: u16,
    exported_symbol_schema: u16,
    output_kind: u8,
    architecture: u8,
    little_endian: bool,
    pointer_width: u8,
    target_abi: u8,
    status_bits: u8,
    required_features: u64,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct AuthorizedTarget {
    host_id: String,
    target_os: String,
    target_arch: String,
    asimd: bool,
    #[serde(default)]
    build_receipt_schema: Option<String>,
    #[serde(default)]
    build_receipt_sha256: Option<String>,
    #[serde(default)]
    discovery_build_receipt_schema: Option<String>,
    #[serde(default)]
    discovery_build_receipt_sha256: Option<String>,
    family_tuple: AuthorizedFamilyTuple,
}

#[derive(Debug, Clone, Deserialize, Serialize, Eq, PartialEq)]
#[serde(deny_unknown_fields)]
struct AuthorizedFamilyTuple {
    compiler_version: u16,
    metadata_version: u16,
    backend_version: u16,
    call_abi_schema: u16,
    exported_symbol_schema: u16,
    output_kind: u8,
    architecture: u8,
    little_endian: bool,
    pointer_width: u8,
    target_abi: u8,
    platform: u8,
    status_bits: u8,
    exported_symbol_n_type: u8,
    required_features: u64,
    manifest_identity: String,
    family_selector: u16,
    minimum_literal_bytes: u32,
    maximum_literal_bytes: u32,
    minimum_window_bytes: u32,
    portable_prefix_candidate_starts: u32,
}

#[derive(Debug, Clone, Deserialize)]
struct CampaignBuildReceipt {
    schema: String,
    host_id: String,
    target_os: String,
    target_arch: String,
    runner_source_sha256: String,
    plan_identity: String,
    analyzer_identity: String,
    evidence_identity: String,
    family_tuple: AuthorizedFamilyTuple,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
struct DiscoveryBuildReceipt {
    schema: String,
    identity_sha256: String,
    runner_revision: String,
    runner_source_sha256: String,
    source_archive_sha256: String,
    private_family_source_sha256: String,
    target_os: String,
    target_arch: String,
    host_id: String,
    backend_name: String,
    backend_tag: u16,
    backend_version: String,
    candidate_policy: u16,
    llvm: bool,
    compiler_identity: String,
    manifest_identity: String,
    discovery_authorization_sha256: Option<String>,
    discovery_build_receipt_sha256: Option<String>,
    family_selector: u16,
    minimum_literal_bytes: u32,
    maximum_literal_bytes: u32,
    minimum_window_bytes: u32,
    portable_prefix_candidate_starts: u32,
    family_tuple: AuthorizedFamilyTuple,
    plan_identity: String,
    analyzer_identity: String,
    evidence_identity: Option<String>,
    timing_permitted: bool,
    object_candidate_manifest_schema: String,
    object_candidate_manifest_sha256: String,
    object_candidate_manifest_payload_sha256: String,
    object_candidate_count: u64,
    literal_dispositions_sha256: String,
    literal_dispositions_payload_sha256: String,
    literal_disposition_count: u64,
    prepared_inputs_sha256: String,
    prepare_source_sha256: String,
    canonical_byte_escaped_sources: bool,
    candidates: Vec<DiscoveryCandidate>,
    refusals: Vec<DiscoveryRefusal>,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
struct DiscoveryCandidate {
    ordinal: u64,
    semantic_candidate_sha256: String,
    literal_sha256: String,
    literal_hex: String,
    compile_identity: String,
    compile_receipt_sha256: String,
    compile_receipt_basename: String,
    implementation_object_sha256: String,
    glue_object_sha256: String,
    implementation_object_basename: String,
    glue_object_basename: String,
    implementation_symbols: DiscoveryImplementationSymbols,
    glue_symbol: String,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
struct DiscoveryImplementationSymbols {
    entry: String,
    payload: String,
    metadata: String,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
struct DiscoveryRefusal {
    ordinal: u64,
    semantic_candidate_sha256: String,
    literal_sha256: String,
    literal_hex: String,
    disposition: String,
    compile_receipt_sha256: String,
    compile_receipt_basename: String,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
struct AuthorizedIdentities {
    evidence_domain_hex: String,
    plan_identity: String,
    analyzer_identity: String,
    evidence_identity: String,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct AuthorizedQualification {
    required_fragment_count: u64,
    required_strata: Vec<String>,
    long_policy_gate_scope: Value,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
struct Analysis {
    schema: String,
    contract_sha256: String,
    analyzer_source_sha256: String,
    runner_source_sha256: String,
    correctness: BTreeMap<String, CorrectnessHost>,
    timing: BTreeMap<String, TimingHost>,
    fragment_count: u64,
    fragment_sha256s: Vec<String>,
    exact_shard_union: bool,
    overlaps: u64,
    omissions: u64,
    long_policy_gate_scope: Value,
    qualification_pass: bool,
    production_authority_granted: bool,
    rebar_accepted_as_input: bool,
    result_derived_exclusions: bool,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
struct CorrectnessHost {
    universal: CorrectnessReceipt,
    #[serde(rename = "long-policy")]
    long_policy: CorrectnessReceipt,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
struct CorrectnessReceipt {
    rows: u64,
    static_rows: u64,
    portable_rows: u64,
    unique_literals: u64,
    pass: bool,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
struct TimingHost {
    #[serde(rename = "long-policy")]
    long_policy: TimingReceipt,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
struct TimingReceipt {
    cells: u64,
    aggregate_cell_geomean: RatioReceipt,
    maximum_cell_ratio: RatioReceipt,
    strict_pair_wins: u64,
    strict_pairs: u64,
    strict_pair_win_fraction: RatioReceipt,
    strata: BTreeMap<String, BTreeMap<String, StratumReceipt>>,
    pass: bool,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
struct RatioReceipt {
    numerator: u64,
    denominator: u64,
    decimal: Value,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
struct StratumReceipt {
    cells: u64,
    geomean: RatioReceipt,
}

#[derive(Debug, Clone)]
struct ContractFacts {
    full_rows: BTreeMap<String, u64>,
    static_rows: BTreeMap<String, u64>,
    portable_rows: BTreeMap<String, u64>,
    long_timing_cells: u64,
    timing_repetitions: u64,
    aggregate_exclusive_maximum: Rational,
    stratum_exclusive_maximum: Rational,
    cell_inclusive_maximum: Rational,
    strict_pair_fraction_minimum: Rational,
    private_intent_domain: Vec<u8>,
}

#[derive(Debug, Clone, Copy, Eq, PartialEq)]
struct Rational {
    numerator: u128,
    denominator: u128,
}

#[derive(Debug, Clone, Copy, Eq, PartialEq)]
enum AuthorityMode {
    Production,
    PrivateDiscovery,
}

impl Rational {
    fn new(numerator: u128, denominator: u128, label: &str) -> Result<Self> {
        if denominator == 0 {
            return fail(format!("{label} has a zero denominator"));
        }
        Ok(Self {
            numerator,
            denominator,
        })
    }

    fn less_than(self, other: Self, label: &str) -> Result<bool> {
        let left = self
            .numerator
            .checked_mul(other.denominator)
            .ok_or_else(|| PromotionError::new(format!("{label} comparison overflow")))?;
        let right = other
            .numerator
            .checked_mul(self.denominator)
            .ok_or_else(|| PromotionError::new(format!("{label} comparison overflow")))?;
        Ok(left < right)
    }

    fn less_than_or_equal(self, other: Self, label: &str) -> Result<bool> {
        Ok(self.less_than(other, label)? || self == other)
    }

    fn greater_than_or_equal(self, other: Self, label: &str) -> Result<bool> {
        Ok(!self.less_than(other, label)?)
    }
}

#[derive(Debug, Clone, Serialize)]
struct RenderedRow {
    selector: u16,
    compiler_version: u16,
    metadata_version: u16,
    backend_version: u16,
    call_abi_schema: u16,
    exported_symbol_schema: u16,
    output_kind: u8,
    architecture: u8,
    little_endian: bool,
    pointer_width: u8,
    target_abi: u8,
    platform: u8,
    status_bits: u8,
    exported_symbol_n_type: u8,
    required_features: u64,
    minimum_literal_bytes: u32,
    maximum_literal_bytes: u32,
    minimum_window_bytes: u32,
    portable_prefix_candidate_starts: u32,
    manifest_identity: String,
    plan_identity: String,
    analyzer_identity: String,
    evidence_identity: String,
    host_id: String,
    target_os: String,
}

#[derive(Debug, Clone)]
pub struct GeneratedTransaction {
    pub source_basename: &'static str,
    pub rust: Vec<u8>,
    pub receipt: Vec<u8>,
    pub sha256sums: Vec<u8>,
    pub committed: Vec<u8>,
}

/// Run the create-only authorization transaction from command-line arguments.
pub fn run_cli(arguments: impl IntoIterator<Item = OsString>) -> Result<()> {
    let arguments = arguments.into_iter().collect::<Vec<_>>();
    match arguments.get(1).map(OsString::as_os_str) {
        Some(command) if command == OsStr::new("authorize-production") && arguments.len() == 9 => {
            run_production_cli(&arguments)
        }
        Some(command) if command == OsStr::new("render-private") && arguments.len() == 8 => {
            run_private_cli(&arguments)
        }
        _ => fail(
            "usage: search-production-family-promotion authorize-production \
             AUTHORIZATION.json AUTHORIZATION_SHA256 CONTRACT.json ANALYSIS.json \
             MACOS_BUILD_RECEIPT.json LINUX_BUILD_RECEIPT.json OUTPUT_DIR\n\
             or: search-production-family-promotion render-private \
             DISCOVERY.json DISCOVERY_SHA256 CONTRACT.json \
             MACOS_DISCOVERY_RECEIPT.json LINUX_DISCOVERY_RECEIPT.json OUTPUT_DIR",
        ),
    }
}

fn run_production_cli(arguments: &[OsString]) -> Result<()> {
    let authorization_path = PathBuf::from(&arguments[2]);
    let authorization_sha256 = arguments[3]
        .to_str()
        .ok_or_else(|| PromotionError::new("authorization SHA-256 is not UTF-8"))?;
    let expected_authorization = decode_sha256(authorization_sha256, "authorization SHA-256")?;
    let contract_path = PathBuf::from(&arguments[4]);
    let analysis_path = PathBuf::from(&arguments[5]);
    let build_receipts = [
        read_bounded_regular(Path::new(&arguments[6]), MAX_INPUT_BYTES)?,
        read_bounded_regular(Path::new(&arguments[7]), MAX_INPUT_BYTES)?,
    ];
    let output_path = PathBuf::from(&arguments[8]);

    let authorization = read_bounded_regular(&authorization_path, MAX_INPUT_BYTES)?;
    require_digest(&authorization, expected_authorization, "authorization file")?;
    let parsed_authorization: Authorization = parse_json(&authorization, "authorization file")?;
    let expected_contract = decode_sha256(
        &parsed_authorization.inputs.contract_sha256,
        "authorized contract SHA-256",
    )?;
    let expected_analysis = decode_sha256(
        &parsed_authorization.inputs.analysis_sha256,
        "authorized analysis SHA-256",
    )?;
    let contract = read_bounded_regular(&contract_path, MAX_INPUT_BYTES)?;
    require_digest(&contract, expected_contract, "campaign contract")?;
    let analysis = read_bounded_regular(&analysis_path, MAX_INPUT_BYTES)?;
    require_digest(&analysis, expected_analysis, "qualification analysis")?;

    let generated = generate_transaction(
        &authorization,
        expected_authorization,
        &contract,
        &analysis,
        &build_receipts,
    )?;
    write_transaction(&output_path, &generated)
}

fn run_private_cli(arguments: &[OsString]) -> Result<()> {
    let authorization_path = PathBuf::from(&arguments[2]);
    let authorization_sha256 = arguments[3]
        .to_str()
        .ok_or_else(|| PromotionError::new("discovery authorization SHA-256 is not UTF-8"))?;
    let expected_authorization =
        decode_sha256(authorization_sha256, "discovery authorization SHA-256")?;
    let contract_path = PathBuf::from(&arguments[4]);
    let discovery_receipts = [
        read_bounded_regular(Path::new(&arguments[5]), MAX_INPUT_BYTES)?,
        read_bounded_regular(Path::new(&arguments[6]), MAX_INPUT_BYTES)?,
    ];
    let output_path = PathBuf::from(&arguments[7]);
    let authorization = read_bounded_regular(&authorization_path, MAX_INPUT_BYTES)?;
    require_digest(
        &authorization,
        expected_authorization,
        "discovery authorization file",
    )?;
    let parsed: PrivateAuthorization = parse_json(&authorization, "discovery authorization file")?;
    let expected_contract = decode_sha256(
        &parsed.payload.campaign_contract_sha256,
        "discovery contract SHA-256",
    )?;
    let contract = read_bounded_regular(&contract_path, MAX_INPUT_BYTES)?;
    require_digest(&contract, expected_contract, "discovery campaign contract")?;
    let generated = generate_private_transaction(
        &authorization,
        expected_authorization,
        &contract,
        &discovery_receipts,
    )?;
    write_transaction(&output_path, &generated)
}

/// Validate all authority and evidence bytes and render the complete output in
/// memory.  No filesystem mutation occurs at this boundary.
pub fn generate_transaction(
    authorization_bytes: &[u8],
    expected_authorization_sha256: [u8; 32],
    contract_bytes: &[u8],
    analysis_bytes: &[u8],
    build_receipt_bytes: &[Vec<u8>],
) -> Result<GeneratedTransaction> {
    require_digest(
        authorization_bytes,
        expected_authorization_sha256,
        "authorization file",
    )?;
    let authorization: Authorization = parse_json(authorization_bytes, "authorization file")?;
    validate_authorization_header(&authorization)?;
    require_authenticated_external_production_gates()?;

    let contract_sha = sha256(contract_bytes);
    let analysis_sha = sha256(analysis_bytes);
    let authorized_contract = decode_sha256(
        &authorization.inputs.contract_sha256,
        "authorized contract SHA-256",
    )?;
    let authorized_analysis = decode_sha256(
        &authorization.inputs.analysis_sha256,
        "authorized analysis SHA-256",
    )?;
    if contract_sha != authorized_contract {
        return fail("campaign contract bytes differ from reviewed authorization");
    }
    if analysis_sha != authorized_analysis {
        return fail("qualification analysis bytes differ from reviewed authorization");
    }

    let contract: Value = parse_json(contract_bytes, "campaign contract")?;
    let contract_facts = validate_contract(
        &authorization.family,
        &authorization.inputs.contract_schema,
        &contract,
    )?;
    let analysis: Analysis = parse_json(analysis_bytes, "qualification analysis")?;
    validate_analysis(
        &authorization,
        &contract_facts,
        &analysis,
        contract_sha,
        analysis_sha,
    )?;
    let build_receipts = validate_build_receipts(
        &authorization.family,
        &authorization.inputs.runner_source_sha256,
        &authorization.identities.plan_identity,
        &authorization.identities.analyzer_identity,
        &authorization.identities.evidence_identity,
        build_receipt_bytes,
    )?;
    let rows = reconstruct_rows(
        &authorization.family,
        &build_receipts,
        &authorization.identities.plan_identity,
        &authorization.identities.analyzer_identity,
        &authorization.identities.evidence_identity,
    )?;

    let rust = render_rust(&rows, false);
    let rust_sha = sha256(&rust);
    let receipt_value = json!({
        "schema": RECEIPT_SCHEMA,
        "authorization_sha256": hex(&expected_authorization_sha256),
        "contract_sha256": hex(&contract_sha),
        "analysis_sha256": hex(&analysis_sha),
        "analysis_schema": analysis.schema,
        "analyzer_source_sha256": authorization.inputs.analyzer_source_sha256,
        "runner_source_sha256": authorization.inputs.runner_source_sha256,
        "build_receipts": build_receipt_inventory(&authorization.family.targets),
        "evidence_derivation": {
            "domain_hex": hex(EVIDENCE_DOMAIN),
            "raw_digest_order": [
                "contract_sha256",
                "analyzer_source_sha256",
                "analysis_sha256"
            ],
            "plan_identity": authorization.identities.plan_identity,
            "analyzer_identity": authorization.identities.analyzer_identity,
            "evidence_identity": authorization.identities.evidence_identity,
        },
        "qualification": {
            "fragment_count": analysis.fragment_count,
            "exact_shard_union": analysis.exact_shard_union,
            "overlaps": analysis.overlaps,
            "omissions": analysis.omissions,
            "qualification_pass": analysis.qualification_pass,
            "production_authority_granted_by_analysis": analysis.production_authority_granted,
            "reviewed_authorization_is_trust_root": true,
            "rebar_accepted_as_input": analysis.rebar_accepted_as_input,
            "result_derived_exclusions": analysis.result_derived_exclusions,
        },
        "rows": rows,
        "rendered_rust_sha256": hex(&rust_sha),
        "production_source_installed": false,
    });
    let receipt = canonical_json(&receipt_value)?;
    let receipt_sha = sha256(&receipt);
    let sha256sums = format!(
        "{}  {OUTPUT_RECEIPT}\n{}  {OUTPUT_RUST}\n",
        hex(&receipt_sha),
        hex(&rust_sha)
    )
    .into_bytes();
    let sha256sums_sha = sha256(&sha256sums);
    let committed = format!(
        "schema={COMMIT_SCHEMA}\nsha256sums_sha256={}\ninventory={OUTPUT_RECEIPT},{OUTPUT_RUST},{OUTPUT_SHA256SUMS},{OUTPUT_COMMITTED}\n",
        hex(&sha256sums_sha)
    )
    .into_bytes();
    Ok(GeneratedTransaction {
        source_basename: OUTPUT_RUST,
        rust,
        receipt,
        sha256sums,
        committed,
    })
}

fn require_authenticated_external_production_gates() -> Result<()> {
    fail(
        "production rendering remains sealed pending SHA-pinned independent application and \
         unopened external-regex heldout analyses",
    )
}

/// Render pre-result private qualification rows from a distinct, externally
/// SHA-pinned discovery authorization.  This path consumes no analyzer result
/// and cannot emit the production source atom.
pub fn generate_private_transaction(
    authorization_bytes: &[u8],
    expected_authorization_sha256: [u8; 32],
    contract_bytes: &[u8],
    discovery_receipt_bytes: &[Vec<u8>],
) -> Result<GeneratedTransaction> {
    require_digest(
        authorization_bytes,
        expected_authorization_sha256,
        "discovery authorization file",
    )?;
    let authorization: PrivateAuthorization =
        parse_json(authorization_bytes, "discovery authorization file")?;
    let family = validate_private_authorization_header(&authorization)?;
    let contract_sha = sha256(contract_bytes);
    let authorized_contract = decode_sha256(
        &authorization.payload.campaign_contract_sha256,
        "discovery contract SHA-256",
    )?;
    if contract_sha != authorized_contract {
        return fail("discovery contract bytes differ from reviewed authorization");
    }
    let contract: Value = parse_json(contract_bytes, "discovery campaign contract")?;
    let facts = validate_contract(&family, &authorization.payload.contract_schema, &contract)?;
    let authorized_domain = facts.private_intent_domain;
    let analyzer_sha = decode_sha256(
        &authorization.payload.analyzer_source_sha256,
        "discovery analyzer source SHA-256",
    )?;
    let intent = private_intent_identity(
        &authorized_domain,
        contract_sha,
        analyzer_sha,
        expected_authorization_sha256,
    );
    let evidence_identity = hex(&intent);
    let authorized_tuples = validate_discovery_build_receipts(
        &family,
        &authorization.payload,
        discovery_receipt_bytes,
    )?;
    let plan_identity = hex(&contract_sha);
    let analyzer_identity = hex(&analyzer_sha);
    let rows = reconstruct_rows(
        &family,
        &authorized_tuples,
        &plan_identity,
        &analyzer_identity,
        &evidence_identity,
    )?;
    let rust = render_rust(&rows, true);
    let rust_sha = sha256(&rust);
    let receipt_value = json!({
        "schema": PRIVATE_RECEIPT_SCHEMA,
        "discovery_authorization_sha256": hex(&expected_authorization_sha256),
        "discovery_authorization_payload_sha256": authorization.payload_sha256,
        "contract_sha256": hex(&contract_sha),
        "analyzer_source_sha256": authorization.payload.analyzer_source_sha256,
        "runner_source_sha256": authorization.payload.discovery_runner_source_sha256,
        "discovery_build_receipts": discovery_build_receipt_inventory(
            &family.targets
        ),
        "discovery_source_pins": {
            "prepared_inputs_sha256": authorization.payload.prepared_inputs_sha256,
            "object_candidate_manifest_schema":
                authorization.payload.object_candidate_manifest_schema,
            "object_candidate_manifest_sha256":
                authorization.payload.object_candidate_manifest_sha256,
            "object_candidate_manifest_payload_sha256":
                authorization.payload.object_candidate_manifest_payload_sha256,
            "literal_dispositions_schema": authorization.payload.literal_dispositions_schema,
            "literal_dispositions_sha256": authorization.payload.literal_dispositions_sha256,
            "literal_dispositions_payload_sha256":
                authorization.payload.literal_dispositions_payload_sha256,
            "prepare_source_sha256": authorization.payload.prepare_source_sha256,
            "discovery_runner_revision": authorization.payload.discovery_runner_revision,
            "discovery_source_archive_sha256":
                authorization.payload.discovery_source_archive_sha256,
            "discovery_identity_sha256": authorization.payload.discovery_identity_sha256,
            "discovery_private_family_source_sha256":
                authorization.payload.discovery_private_family_source_sha256,
            "compiler_identity": authorization.payload.family_common.compiler.identity,
        },
        "intent_derivation": {
            "domain_hex": hex(&authorized_domain),
            "raw_digest_order": [
                "contract_sha256",
                "analyzer_source_sha256",
                "discovery_authorization_sha256"
            ],
            "plan_identity": plan_identity,
            "analyzer_identity": analyzer_identity,
            "intent_evidence_identity": evidence_identity,
        },
        "authority_state": {
            "pre_result_campaign_intent": true,
            "private_qualification_only": true,
            "production_source_authorized": false,
            "analysis_consumed": false,
            "rebar_accepted_as_input": false,
            "result_derived_exclusions": false,
        },
        "rows": rows,
        "rendered_rust_sha256": hex(&rust_sha),
        "private_source_installed": false,
    });
    let receipt = canonical_json(&receipt_value)?;
    let receipt_sha = sha256(&receipt);
    let sha256sums = format!(
        "{}  {OUTPUT_RECEIPT}\n{}  {PRIVATE_OUTPUT_RUST}\n",
        hex(&receipt_sha),
        hex(&rust_sha)
    )
    .into_bytes();
    let sha256sums_sha = sha256(&sha256sums);
    let committed = format!(
        "schema={PRIVATE_COMMIT_SCHEMA}\nsha256sums_sha256={}\ninventory={OUTPUT_RECEIPT},{PRIVATE_OUTPUT_RUST},{OUTPUT_SHA256SUMS},{OUTPUT_COMMITTED}\n",
        hex(&sha256sums_sha)
    )
    .into_bytes();
    Ok(GeneratedTransaction {
        source_basename: PRIVATE_OUTPUT_RUST,
        rust,
        receipt,
        sha256sums,
        committed,
    })
}

fn validate_authorization_header(authorization: &Authorization) -> Result<()> {
    if authorization.schema != AUTHORIZATION_SCHEMA {
        return fail("authorization schema changed");
    }
    let decision = &authorization.decision;
    if !decision.production_source_projection_authorized
        || !decision.analyzer_is_not_deployment_authority
        || !decision.targets_reviewed_as_one_class
        || decision.rebar_accepted_as_input
        || decision.result_derived_exclusions_authorized
    {
        return fail("reviewed authorization decision is incomplete or contaminated");
    }
    if authorization.family.compiler_profile != COMPILER_PROFILE {
        return fail("production authorization selected an unsupported compiler profile");
    }
    let expected_domain = hex(EVIDENCE_DOMAIN);
    if authorization.identities.evidence_domain_hex != expected_domain {
        return fail("evidence domain differs from the reviewed tag30 derivation");
    }
    validate_family_authority(
        &authorization.family,
        &authorization.qualification,
        AuthorityMode::Production,
    )
}

fn validate_private_authorization_header(
    authorization: &PrivateAuthorization,
) -> Result<AuthorizedFamily> {
    if authorization.schema != PRIVATE_AUTHORIZATION_SCHEMA {
        return fail("discovery authorization schema changed");
    }
    let payload_value = serde_json::to_value(&authorization.payload)
        .map_err(|error| PromotionError::new(format!("cannot canonicalize payload: {error}")))?;
    let payload_bytes = serde_json::to_vec(&payload_value)
        .map_err(|error| PromotionError::new(format!("cannot serialize payload: {error}")))?;
    if !payload_bytes.is_ascii() {
        return fail("discovery authorization payload is not canonical ASCII JSON");
    }
    let payload_sha = decode_sha256(
        &authorization.payload_sha256,
        "discovery authorization payload SHA-256",
    )?;
    require_digest(
        &payload_bytes,
        payload_sha,
        "canonical discovery authorization payload",
    )?;

    let payload = &authorization.payload;
    let decision = &payload.decision;
    if !decision.private_projection
        || decision.production_projection
        || !decision.pre_result_intent
        || !decision.analyzer_not_deployment_authority
        || !decision.targets_one_class
        || decision.rebar_permitted
        || decision.result_derived_exclusions
    {
        return fail("discovery authorization state is incomplete or production-confused");
    }
    for (label, digest) in [
        ("campaign contract", &payload.campaign_contract_sha256),
        ("analyzer source", &payload.analyzer_source_sha256),
        ("prepared inputs", &payload.prepared_inputs_sha256),
        (
            "object candidate manifest",
            &payload.object_candidate_manifest_sha256,
        ),
        (
            "object candidate manifest payload",
            &payload.object_candidate_manifest_payload_sha256,
        ),
        ("literal dispositions", &payload.literal_dispositions_sha256),
        (
            "literal dispositions payload",
            &payload.literal_dispositions_payload_sha256,
        ),
        ("prepare source", &payload.prepare_source_sha256),
        (
            "discovery runner source",
            &payload.discovery_runner_source_sha256,
        ),
        (
            "discovery source archive",
            &payload.discovery_source_archive_sha256,
        ),
        ("discovery identity", &payload.discovery_identity_sha256),
        (
            "discovery private family source",
            &payload.discovery_private_family_source_sha256,
        ),
        (
            "compiler identity",
            &payload.family_common.compiler.identity,
        ),
    ] {
        decode_sha256(digest, &format!("{label} SHA-256"))?;
    }
    if payload.contract_schema.is_empty()
        || payload.object_candidate_manifest_schema.is_empty()
        || payload.literal_dispositions_schema.is_empty()
        || !canonical_revision(&payload.discovery_runner_revision)
    {
        return fail("discovery authorization schema or runner revision is not canonical");
    }
    let common = &payload.family_common;
    if common.backend.llvm
        || common.wire.aot_magic_hex != TAG30_AOT_MAGIC_HEX
        || common.wire.static_abi != STATIC_ABI_SCHEMA
        || common.wire.output != OUTPUT_TYPE
        || common.wire.link_interface_schema != LINK_INTERFACE_SCHEMA
    {
        return fail("private family common compiler/wire authority changed");
    }
    if payload.targets.len() != 2 {
        return fail("private authorization target set is partial");
    }
    let mut targets = Vec::with_capacity(2);
    for (name, target) in &payload.targets {
        let expected_name = match target.target_os.as_str() {
            "macos" => "macos_aarch64",
            "linux" => "linux_aarch64",
            _ => return fail("private authorization target OS is unsupported"),
        };
        if name != expected_name
            || target.target_arch != "aarch64"
            || target.manifest_identity != target.family_tuple.manifest_identity
            || target.discovery_build_receipt_schema != BUILD_RECEIPT_SCHEMA
        {
            return fail("private authorization target identity or tuple is mixed");
        }
        targets.push(AuthorizedTarget {
            host_id: target.host_id.clone(),
            target_os: target.target_os.clone(),
            target_arch: target.target_arch.clone(),
            asimd: true,
            build_receipt_schema: None,
            build_receipt_sha256: None,
            discovery_build_receipt_schema: Some(target.discovery_build_receipt_schema.clone()),
            discovery_build_receipt_sha256: Some(target.discovery_build_receipt_sha256.clone()),
            family_tuple: target.family_tuple.clone(),
        });
    }
    let tuple = &targets[0].family_tuple;
    let envelope = &common.envelope;
    let family = AuthorizedFamily {
        selector: envelope.family_selector,
        backend_tag: common.backend.tag,
        backend_name: common.backend.name.clone(),
        backend_version: common.backend.version.clone(),
        candidate_policy: common.backend.candidate_policy,
        aot_magic_hex: common.wire.aot_magic_hex.clone(),
        compiler_profile: COMPILER_PROFILE.to_owned(),
        minimum_literal_bytes: envelope.minimum_literal_bytes,
        maximum_literal_bytes: envelope.maximum_literal_bytes,
        minimum_window_bytes: envelope.minimum_window_bytes,
        portable_prefix_candidate_starts: envelope.portable_prefix_candidate_starts,
        wire: AuthorizedWireProfile {
            compiler_version: tuple.compiler_version,
            metadata_version: tuple.metadata_version,
            backend_version: tuple.backend_version,
            call_abi_schema: tuple.call_abi_schema,
            exported_symbol_schema: tuple.exported_symbol_schema,
            output_kind: tuple.output_kind,
            architecture: tuple.architecture,
            little_endian: tuple.little_endian,
            pointer_width: tuple.pointer_width,
            target_abi: tuple.target_abi,
            status_bits: tuple.status_bits,
            required_features: tuple.required_features,
        },
        targets,
    };
    validate_family_authority(
        &family,
        &payload.qualification,
        AuthorityMode::PrivateDiscovery,
    )?;
    Ok(family)
}

fn canonical_revision(value: &str) -> bool {
    (7..=64).contains(&value.len())
        && value
            .bytes()
            .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase())
}

fn validate_family_authority(
    family: &AuthorizedFamily,
    qualification: &AuthorizedQualification,
    mode: AuthorityMode,
) -> Result<()> {
    if family.selector == 0 {
        return fail("authorized family selector is zero");
    }
    if family.minimum_literal_bytes == 0
        || family.minimum_literal_bytes > family.maximum_literal_bytes
        || family.minimum_window_bytes == 0
        || family.portable_prefix_candidate_starts == 0
    {
        return fail("authorized execution envelope is not canonical");
    }
    let prefix_window = family
        .portable_prefix_candidate_starts
        .checked_add(family.maximum_literal_bytes)
        .and_then(|value| value.checked_sub(1))
        .ok_or_else(|| PromotionError::new("authorized prefix envelope overflow"))?;
    if family.minimum_window_bytes < prefix_window {
        return fail("authorized minimum window cannot contain its portable prefix");
    }
    if qualification.required_fragment_count == 0 {
        return fail("authorization requires no qualification fragments");
    }
    let strata = qualification
        .required_strata
        .iter()
        .collect::<BTreeSet<_>>();
    if strata.len() != qualification.required_strata.len() || strata.is_empty() {
        return fail("authorized stratum dimensions are empty or duplicated");
    }
    validate_wire_profile(&family.wire)?;
    validate_target_authority(family, mode)?;
    Ok(())
}

fn validate_wire_profile(wire: &AuthorizedWireProfile) -> Result<()> {
    if AOT_SEARCH_COMPILER_VERSION_V1 != AOT_LINUX_SEARCH_COMPILER_VERSION_V1 {
        return fail("macOS and Linux Search compiler versions diverged");
    }
    if wire.compiler_version != AOT_SEARCH_COMPILER_VERSION_V1
        || wire.metadata_version != SEARCH_METADATA_VERSION_V1
        || wire.backend_version == 0
        || wire.call_abi_schema != SEARCH_CALL_ABI_SCHEMA_V1
        || wire.exported_symbol_schema != SEARCH_EXPORTED_SYMBOL_SCHEMA_VERSION_V1
        || wire.output_kind != SEARCH_SPAN_OUTPUT_KIND_V1
        || wire.architecture != SEARCH_ARCHITECTURE_AARCH64_V1
        || !wire.little_endian
        || wire.pointer_width != SEARCH_POINTER_WIDTH_V1
        || wire.target_abi != SEARCH_TARGET_ABI_AAPCS64_V1
        || wire.status_bits != SEARCH_STATUS_BITS_V1
        || wire.required_features != SEARCH_REQUIRED_ASIMD_FEATURES_V1
    {
        return fail("authorized compiler/backend/ABI/ISA wire profile is not canonical");
    }
    Ok(())
}

fn validate_target_authority(family: &AuthorizedFamily, mode: AuthorityMode) -> Result<()> {
    let targets = &family.targets;
    if targets.len() != 2 {
        return fail("one macOS and one Linux target must be authorized together");
    }
    let mut hosts = BTreeSet::new();
    let mut systems = BTreeSet::new();
    let mut receipt_hashes = BTreeSet::new();
    for target in targets {
        if target.host_id.is_empty()
            || !hosts.insert(target.host_id.as_str())
            || !systems.insert(target.target_os.as_str())
            || target.target_arch != "aarch64"
            || !target.asimd
        {
            return fail("authorized target set is duplicated or not AArch64 ASIMD");
        }
        match (
            mode,
            target.build_receipt_schema.as_deref(),
            target.build_receipt_sha256.as_deref(),
            target.discovery_build_receipt_schema.as_deref(),
            target.discovery_build_receipt_sha256.as_deref(),
        ) {
            (AuthorityMode::Production, Some(BUILD_RECEIPT_SCHEMA), Some(digest), None, None)
            | (
                AuthorityMode::PrivateDiscovery,
                None,
                None,
                Some(BUILD_RECEIPT_SCHEMA),
                Some(digest),
            ) => {
                let receipt_hash =
                    decode_sha256(digest, &format!("{} build receipt SHA-256", target.host_id))?;
                if !receipt_hashes.insert(receipt_hash) {
                    return fail("authorized build receipt SHA-256s are duplicated");
                }
            }
            (AuthorityMode::Production, _, _, _, _) => {
                return fail("production authorization lacks one exact sealed build receipt");
            }
            (AuthorityMode::PrivateDiscovery, _, _, _, _) => {
                return fail("private authorization must pin only pre-render discovery receipts");
            }
        }
        validate_family_tuple(family, target)?;
    }
    if systems != BTreeSet::from(["linux", "macos"]) {
        return fail("authorized target set is not exactly macOS plus Linux");
    }
    let macos = targets
        .iter()
        .find(|target| target.target_os == "macos")
        .ok_or_else(|| PromotionError::new("authorized macOS target is missing"))?;
    let linux = targets
        .iter()
        .find(|target| target.target_os == "linux")
        .ok_or_else(|| PromotionError::new("authorized Linux target is missing"))?;
    if !tuples_differ_only_in_target_fields(&macos.family_tuple, &linux.family_tuple) {
        return fail("macOS and Linux family tuples differ outside target-specific fields");
    }
    Ok(())
}

fn validate_family_tuple(family: &AuthorizedFamily, target: &AuthorizedTarget) -> Result<()> {
    let tuple = &target.family_tuple;
    let wire = &family.wire;
    if tuple.compiler_version != wire.compiler_version
        || tuple.metadata_version != wire.metadata_version
        || tuple.backend_version != wire.backend_version
        || tuple.backend_version != family.backend_tag
        || tuple.call_abi_schema != wire.call_abi_schema
        || tuple.exported_symbol_schema != wire.exported_symbol_schema
        || tuple.output_kind != wire.output_kind
        || tuple.architecture != wire.architecture
        || tuple.little_endian != wire.little_endian
        || tuple.pointer_width != wire.pointer_width
        || tuple.target_abi != wire.target_abi
        || tuple.status_bits != wire.status_bits
        || tuple.required_features != wire.required_features
        || tuple.family_selector != family.selector
        || tuple.minimum_literal_bytes != family.minimum_literal_bytes
        || tuple.maximum_literal_bytes != family.maximum_literal_bytes
        || tuple.minimum_window_bytes != family.minimum_window_bytes
        || tuple.portable_prefix_candidate_starts != family.portable_prefix_candidate_starts
    {
        return fail(format!(
            "{} build family tuple differs from its authorized compiler/ABI/envelope",
            target.host_id
        ));
    }
    decode_sha256(
        &tuple.manifest_identity,
        &format!("{} manifest identity", target.host_id),
    )?;
    match target.target_os.as_str() {
        "macos"
            if tuple.platform == SEARCH_PLATFORM_MACOS_V1
                && tuple.exported_symbol_n_type == SEARCH_EXPORTED_SYMBOL_N_TYPE_V1 => {}
        "linux"
            if tuple.platform == SEARCH_PLATFORM_LINUX_V1
                && tuple.exported_symbol_n_type == SEARCH_EXPORTED_SYMBOL_INFO_ELF_FUNCTION_V1 => {}
        _ => return fail("authorized target platform or symbol ABI is inconsistent"),
    }
    Ok(())
}

fn tuples_differ_only_in_target_fields(
    left: &AuthorizedFamilyTuple,
    right: &AuthorizedFamilyTuple,
) -> bool {
    left.compiler_version == right.compiler_version
        && left.metadata_version == right.metadata_version
        && left.backend_version == right.backend_version
        && left.call_abi_schema == right.call_abi_schema
        && left.exported_symbol_schema == right.exported_symbol_schema
        && left.output_kind == right.output_kind
        && left.architecture == right.architecture
        && left.little_endian == right.little_endian
        && left.pointer_width == right.pointer_width
        && left.target_abi == right.target_abi
        && left.status_bits == right.status_bits
        && left.required_features == right.required_features
        && left.family_selector == right.family_selector
        && left.minimum_literal_bytes == right.minimum_literal_bytes
        && left.maximum_literal_bytes == right.maximum_literal_bytes
        && left.minimum_window_bytes == right.minimum_window_bytes
        && left.portable_prefix_candidate_starts == right.portable_prefix_candidate_starts
}

fn validate_build_receipts(
    family: &AuthorizedFamily,
    runner_source_sha256: &str,
    plan_identity: &str,
    analyzer_identity: &str,
    evidence_identity: &str,
    receipt_bytes: &[Vec<u8>],
) -> Result<BTreeMap<String, AuthorizedFamilyTuple>> {
    if receipt_bytes.len() != family.targets.len() {
        return fail("build receipt set is partial");
    }
    decode_sha256(runner_source_sha256, "runner source SHA-256")?;
    decode_sha256(plan_identity, "build receipt plan identity")?;
    decode_sha256(analyzer_identity, "build receipt analyzer identity")?;
    decode_sha256(evidence_identity, "build receipt evidence identity")?;

    let authorized = family
        .targets
        .iter()
        .map(|target| {
            (
                target
                    .build_receipt_sha256
                    .as_deref()
                    .expect("production target validation requires a receipt hash"),
                target,
            )
        })
        .collect::<BTreeMap<_, _>>();
    let mut tuples = BTreeMap::new();
    let mut observed_receipts = BTreeSet::new();
    for bytes in receipt_bytes {
        let digest = hex(&sha256(bytes));
        let Some(target) = authorized.get(digest.as_str()) else {
            return fail("build receipt bytes differ from reviewed authorization");
        };
        if !observed_receipts.insert(digest) {
            return fail("build receipt set contains a duplicate");
        }
        let receipt: CampaignBuildReceipt = parse_json(bytes, "campaign build receipt")?;
        if receipt.schema != BUILD_RECEIPT_SCHEMA
            || Some(receipt.schema.as_str()) != target.build_receipt_schema.as_deref()
            || receipt.host_id != target.host_id
            || receipt.target_os != target.target_os
            || receipt.target_arch != target.target_arch
            || receipt.runner_source_sha256 != runner_source_sha256
            || receipt.plan_identity != plan_identity
            || receipt.analyzer_identity != analyzer_identity
            || receipt.evidence_identity != evidence_identity
            || receipt.family_tuple != target.family_tuple
        {
            return fail(format!(
                "{} build receipt is mixed or differs from its reviewed tuple",
                target.host_id
            ));
        }
        if tuples
            .insert(target.target_os.clone(), receipt.family_tuple)
            .is_some()
        {
            return fail("build receipt target set is duplicated");
        }
    }
    if observed_receipts.len() != authorized.len() || tuples.len() != family.targets.len() {
        return fail("build receipt set is partial");
    }
    Ok(tuples)
}

fn validate_discovery_build_receipts(
    family: &AuthorizedFamily,
    authorization: &PrivateAuthorizationPayload,
    receipt_bytes: &[Vec<u8>],
) -> Result<BTreeMap<String, AuthorizedFamilyTuple>> {
    if receipt_bytes.len() != family.targets.len() {
        return fail("discovery build receipt set is partial");
    }
    let runner_source_sha256 = &authorization.discovery_runner_source_sha256;
    let authorized = family
        .targets
        .iter()
        .map(|target| {
            (
                target
                    .discovery_build_receipt_sha256
                    .as_deref()
                    .expect("private target validation requires a discovery receipt hash"),
                target,
            )
        })
        .collect::<BTreeMap<_, _>>();
    let mut tuples = BTreeMap::new();
    let mut observed_receipts = BTreeSet::new();
    for bytes in receipt_bytes {
        let digest = hex(&sha256(bytes));
        let Some(target) = authorized.get(digest.as_str()) else {
            return fail("discovery build receipt bytes differ from reviewed authorization");
        };
        if !observed_receipts.insert(digest) {
            return fail("discovery build receipt set contains a duplicate");
        }
        let receipt: DiscoveryBuildReceipt =
            parse_json(bytes, "pre-render discovery build receipt")?;
        if Some(receipt.schema.as_str()) != target.discovery_build_receipt_schema.as_deref()
            || receipt.timing_permitted
            || receipt.evidence_identity.is_some()
            || receipt.discovery_authorization_sha256.is_some()
            || receipt.discovery_build_receipt_sha256.is_some()
            || receipt.host_id != target.host_id
            || receipt.target_os != target.target_os
            || receipt.target_arch != target.target_arch
            || receipt.manifest_identity != target.family_tuple.manifest_identity
            || receipt.manifest_identity != receipt.family_tuple.manifest_identity
            || receipt.runner_revision != authorization.discovery_runner_revision
            || receipt.runner_source_sha256 != runner_source_sha256.as_str()
            || receipt.source_archive_sha256 != authorization.discovery_source_archive_sha256
            || receipt.private_family_source_sha256
                != authorization.discovery_private_family_source_sha256
            || receipt.identity_sha256 != authorization.discovery_identity_sha256
            || receipt.backend_name != authorization.family_common.backend.name
            || receipt.backend_tag != authorization.family_common.backend.tag
            || receipt.backend_version != authorization.family_common.backend.version
            || receipt.candidate_policy != authorization.family_common.backend.candidate_policy
            || receipt.llvm
            || receipt.compiler_identity != authorization.family_common.compiler.identity
            || receipt.family_selector != authorization.family_common.envelope.family_selector
            || receipt.minimum_literal_bytes
                != authorization.family_common.envelope.minimum_literal_bytes
            || receipt.maximum_literal_bytes
                != authorization.family_common.envelope.maximum_literal_bytes
            || receipt.minimum_window_bytes
                != authorization.family_common.envelope.minimum_window_bytes
            || receipt.portable_prefix_candidate_starts
                != authorization
                    .family_common
                    .envelope
                    .portable_prefix_candidate_starts
            || receipt.plan_identity != authorization.campaign_contract_sha256
            || receipt.analyzer_identity != authorization.analyzer_source_sha256
            || receipt.object_candidate_manifest_schema
                != authorization.object_candidate_manifest_schema
            || receipt.object_candidate_manifest_sha256
                != authorization.object_candidate_manifest_sha256
            || receipt.object_candidate_manifest_payload_sha256
                != authorization.object_candidate_manifest_payload_sha256
            || receipt.literal_dispositions_sha256 != authorization.literal_dispositions_sha256
            || receipt.literal_dispositions_payload_sha256
                != authorization.literal_dispositions_payload_sha256
            || receipt.prepared_inputs_sha256 != authorization.prepared_inputs_sha256
            || receipt.prepare_source_sha256 != authorization.prepare_source_sha256
            || !receipt.canonical_byte_escaped_sources
            || receipt.family_tuple != target.family_tuple
        {
            return fail(format!(
                "{} discovery build receipt is mixed or differs from its reviewed tuple",
                target.host_id
            ));
        }
        validate_discovery_inventory(&receipt, &authorization.family_common.envelope)?;
        if tuples
            .insert(target.target_os.clone(), receipt.family_tuple)
            .is_some()
        {
            return fail("discovery build receipt target set is duplicated");
        }
    }
    if observed_receipts.len() != authorized.len() || tuples.len() != family.targets.len() {
        return fail("discovery build receipt set is partial");
    }
    Ok(tuples)
}

fn validate_discovery_inventory(
    receipt: &DiscoveryBuildReceipt,
    envelope: &PrivateEnvelope,
) -> Result<()> {
    let candidate_count = u64::try_from(receipt.candidates.len())
        .map_err(|_| PromotionError::new("discovery candidate count exceeds u64"))?;
    let refusal_count = u64::try_from(receipt.refusals.len())
        .map_err(|_| PromotionError::new("discovery refusal count exceeds u64"))?;
    if receipt.object_candidate_count != candidate_count
        || candidate_count.checked_add(refusal_count) != Some(receipt.literal_disposition_count)
    {
        return fail("discovery candidate/refusal counts are partial or inconsistent");
    }
    let mut candidate_ordinals = BTreeSet::new();
    for candidate in &receipt.candidates {
        validate_discovery_literal(
            candidate.ordinal,
            &candidate.semantic_candidate_sha256,
            &candidate.literal_sha256,
            &candidate.literal_hex,
            envelope.minimum_literal_bytes,
            envelope.maximum_literal_bytes,
            &mut candidate_ordinals,
        )?;
        for (label, digest) in [
            ("compile identity", &candidate.compile_identity),
            ("compile receipt", &candidate.compile_receipt_sha256),
            (
                "implementation object",
                &candidate.implementation_object_sha256,
            ),
            ("glue object", &candidate.glue_object_sha256),
        ] {
            decode_sha256(digest, &format!("candidate {label} SHA-256"))?;
        }
        for basename in [
            &candidate.compile_receipt_basename,
            &candidate.implementation_object_basename,
            &candidate.glue_object_basename,
        ] {
            if !canonical_basename(basename) {
                return fail("discovery candidate basename is not canonical");
            }
        }
        for symbol in [
            &candidate.implementation_symbols.entry,
            &candidate.implementation_symbols.payload,
            &candidate.implementation_symbols.metadata,
            &candidate.glue_symbol,
        ] {
            if !canonical_symbol(symbol) {
                return fail("discovery candidate symbol is not canonical");
            }
        }
    }
    let mut refusal_ordinals = BTreeSet::new();
    for refusal in &receipt.refusals {
        validate_discovery_literal(
            refusal.ordinal,
            &refusal.semantic_candidate_sha256,
            &refusal.literal_sha256,
            &refusal.literal_hex,
            1,
            envelope.maximum_literal_bytes,
            &mut refusal_ordinals,
        )?;
        decode_sha256(
            &refusal.compile_receipt_sha256,
            "refusal compile receipt SHA-256",
        )?;
        if !canonical_basename(&refusal.compile_receipt_basename)
            || refusal.disposition.is_empty()
            || !refusal.disposition.bytes().all(|byte| {
                byte.is_ascii_lowercase() || byte.is_ascii_digit() || matches!(byte, b'_' | b'-')
            })
        {
            return fail("discovery refusal disposition or basename is not canonical");
        }
    }
    if u64::try_from(candidate_ordinals.len()).ok() != Some(candidate_count)
        || (0..candidate_count).any(|ordinal| !candidate_ordinals.contains(&ordinal))
        || u64::try_from(refusal_ordinals.len()).ok() != Some(refusal_count)
        || (0..refusal_count).any(|ordinal| !refusal_ordinals.contains(&ordinal))
    {
        return fail("discovery candidates or refusals do not cover exact local ordinals");
    }
    Ok(())
}

fn validate_discovery_literal(
    ordinal: u64,
    semantic_candidate_sha256: &str,
    literal_sha256: &str,
    literal_hex: &str,
    minimum_literal_bytes: u32,
    maximum_literal_bytes: u32,
    ordinals: &mut BTreeSet<u64>,
) -> Result<()> {
    decode_sha256(semantic_candidate_sha256, "semantic candidate SHA-256")?;
    let literal = decode_hex_bytes(literal_hex, "discovery literal bytes")?;
    let literal_len = u32::try_from(literal.len())
        .map_err(|_| PromotionError::new("discovery literal length exceeds u32"))?;
    if literal_len < minimum_literal_bytes
        || literal_len > maximum_literal_bytes
        || decode_sha256(literal_sha256, "discovery literal SHA-256")? != sha256(&literal)
        || !ordinals.insert(ordinal)
    {
        return fail("discovery literal identity, width, or ordinal is invalid");
    }
    Ok(())
}

fn canonical_basename(value: &str) -> bool {
    !value.is_empty()
        && value != "."
        && value != ".."
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b'-' | b'.'))
}

fn canonical_symbol(value: &str) -> bool {
    let mut bytes = value.bytes();
    bytes
        .next()
        .is_some_and(|byte| byte.is_ascii_alphabetic() || byte == b'_')
        && bytes.all(|byte| byte.is_ascii_alphanumeric() || byte == b'_')
}

fn build_receipt_inventory(targets: &[AuthorizedTarget]) -> Vec<Value> {
    let mut targets = targets.iter().collect::<Vec<_>>();
    targets.sort_by(|left, right| left.target_os.cmp(&right.target_os));
    targets
        .into_iter()
        .map(|target| {
            json!({
                "host_id": target.host_id,
                "target_os": target.target_os,
                "schema": target.build_receipt_schema.as_deref().expect(
                    "production target validation requires a receipt schema"
                ),
                "sha256": target.build_receipt_sha256.as_deref().expect(
                    "production target validation requires a receipt hash"
                ),
                "family_tuple": target.family_tuple,
            })
        })
        .collect()
}

fn discovery_build_receipt_inventory(targets: &[AuthorizedTarget]) -> Vec<Value> {
    let mut targets = targets.iter().collect::<Vec<_>>();
    targets.sort_by(|left, right| left.target_os.cmp(&right.target_os));
    targets
        .into_iter()
        .map(|target| {
            json!({
                "host_id": target.host_id,
                "target_os": target.target_os,
                "schema": target.discovery_build_receipt_schema.as_deref().expect(
                    "private target validation requires a discovery receipt schema"
                ),
                "sha256": target.discovery_build_receipt_sha256.as_deref().expect(
                    "private target validation requires a discovery receipt hash"
                ),
                "family_tuple": target.family_tuple,
            })
        })
        .collect()
}

fn validate_contract(
    family: &AuthorizedFamily,
    contract_schema: &str,
    contract: &Value,
) -> Result<ContractFacts> {
    let root = object(contract, "campaign contract")?;
    require_string(root, "schema", "campaign contract")?
        .eq(contract_schema)
        .then_some(())
        .ok_or_else(|| {
            PromotionError::new("campaign contract schema differs from authorization")
        })?;
    require_bool(root, "result_blind", "campaign contract", true)?;
    require_empty_array(root, "rebar_inputs", "campaign contract")?;
    require_bool(root, "result_derived_selection", "campaign contract", false)?;
    require_bool(
        root,
        "result_derived_exclusions",
        "campaign contract",
        false,
    )?;

    let backend = object(
        required(root, "backend", "campaign contract")?,
        "campaign contract backend",
    )?;
    if require_u64(backend, "tag", "campaign backend")? != u64::from(family.backend_tag)
        || require_string(backend, "name", "campaign backend")? != family.backend_name
        || require_string(backend, "version", "campaign backend")? != family.backend_version
        || require_u64(backend, "candidate_policy", "campaign backend")?
            != u64::from(family.candidate_policy)
        || require_string(backend, "aot_magic_hex", "campaign backend")? != family.aot_magic_hex
    {
        return fail("campaign backend differs from the exact authorized family");
    }
    require_bool(backend, "llvm", "campaign backend", false)?;

    let hosts = array(
        required(root, "hosts", "campaign contract")?,
        "campaign hosts",
    )?;
    if hosts.len() != family.targets.len() {
        return fail("campaign host count differs from authorization");
    }
    let authorized_hosts = family
        .targets
        .iter()
        .map(|target| (target.host_id.as_str(), target))
        .collect::<BTreeMap<_, _>>();
    let mut observed_hosts = BTreeSet::new();
    for host in hosts {
        let host = object(host, "campaign host")?;
        let id = require_string(host, "id", "campaign host")?;
        let Some(authorized) = authorized_hosts.get(id) else {
            return fail(format!("campaign host {id:?} is not authorized"));
        };
        if !observed_hosts.insert(id)
            || require_string(host, "target_os", "campaign host")? != authorized.target_os
            || require_string(host, "target_arch", "campaign host")? != authorized.target_arch
        {
            return fail(format!("campaign host {id:?} target identity changed"));
        }
        require_bool(host, "asimd", "campaign host", authorized.asimd)?;
    }

    let projections = object(
        required(root, "projections", "campaign contract")?,
        "campaign projections",
    )?;
    let mut full_rows = BTreeMap::new();
    let mut static_rows = BTreeMap::new();
    let mut portable_rows = BTreeMap::new();
    let mut timed_rows = BTreeMap::new();
    for name in ["universal", "long-policy"] {
        let projection = object(
            required(projections, name, "campaign projections")?,
            &format!("{name} projection"),
        )?;
        let full = require_u64(projection, "full_rows", name)?;
        let statics = require_u64(projection, "correctness_static_rows", name)?;
        let portable = require_u64(projection, "correctness_portable_rows", name)?;
        if statics.checked_add(portable) != Some(full) || full == 0 {
            return fail(format!("{name} correctness projection is incomplete"));
        }
        require_hex_field(projection, "full_sha256", name)?;
        require_hex_field(projection, "timed_sha256", name)?;
        full_rows.insert(name.to_owned(), full);
        static_rows.insert(name.to_owned(), statics);
        portable_rows.insert(name.to_owned(), portable);
        timed_rows.insert(
            name.to_owned(),
            require_u64(projection, "timed_rows", name)?,
        );
        if name == "long-policy"
            && require_u64(projection, "production_input_floor_bytes", name)?
                != u64::from(family.minimum_window_bytes)
        {
            return fail("long-policy floor differs from authorized production row");
        }
    }

    let sharding = object(
        required(root, "sharding", "campaign contract")?,
        "campaign sharding",
    )?;
    let shards = require_u64(sharding, "shards", "campaign sharding")?;
    let concurrent_workers = require_u64(sharding, "concurrent_workers", "campaign sharding")?;
    if shards == 0 || concurrent_workers == 0 || concurrent_workers > shards {
        return fail("campaign sharding has an invalid shard or concurrency count");
    }
    validate_ranges(
        required(sharding, "correctness_ranges", "campaign sharding")?,
        shards,
        full_rows["universal"],
        "correctness ranges",
    )?;
    validate_ranges(
        required(sharding, "universal_timing_ranges", "campaign sharding")?,
        shards,
        timed_rows["universal"],
        "universal timing ranges",
    )?;
    validate_ranges(
        required(sharding, "long_policy_timing_ranges", "campaign sharding")?,
        shards,
        timed_rows["long-policy"],
        "long-policy timing ranges",
    )?;

    let gates = object(
        required(root, "long_policy_gates", "campaign contract")?,
        "long-policy gates",
    )?;
    require_bool(
        gates,
        "one_failure_rejects_whole_class",
        "long-policy gates",
        true,
    )?;
    require_bool(
        gates,
        "result_derived_exclusions",
        "long-policy gates",
        false,
    )?;
    let aggregate_exclusive_maximum = decimal_value(
        required(
            gates,
            "aggregate_candidate_over_portable_exclusive_maximum",
            "long-policy gates",
        )?,
        "aggregate exclusive maximum",
    )?;
    let stratum_exclusive_maximum = decimal_value(
        required(
            gates,
            "each_width_geomean_exclusive_maximum",
            "long-policy gates",
        )?,
        "stratum exclusive maximum",
    )?;
    for field in [
        "each_topology_geomean_exclusive_maximum",
        "each_window_geomean_exclusive_maximum",
        "each_outcome_geomean_exclusive_maximum",
        "each_learned_source_kind_geomean_exclusive_maximum",
    ] {
        if decimal_value(required(gates, field, "long-policy gates")?, field)?
            != stratum_exclusive_maximum
        {
            return fail("long-policy stratum gates are not one closed threshold");
        }
    }
    let cell_inclusive_maximum = decimal_value(
        required(
            gates,
            "individual_cell_inclusive_maximum",
            "long-policy gates",
        )?,
        "cell inclusive maximum",
    )?;
    let strict_pair_fraction_minimum = decimal_value(
        required(
            gates,
            "strict_pair_win_fraction_minimum",
            "long-policy gates",
        )?,
        "strict pair fraction minimum",
    )?;
    let timing_repetitions = require_u64(gates, "timing_repetitions", "long-policy gates")?;
    if timing_repetitions == 0 {
        return fail("long-policy timing repetition count is zero");
    }
    let private_family_authority = object(
        required(root, "private_family_authority", "campaign contract")?,
        "private family authority",
    )?;
    if require_u64(
        private_family_authority,
        "family_selector",
        "private family authority",
    )? != u64::from(family.selector)
        || require_u64(
            private_family_authority,
            "minimum_literal_bytes",
            "private family authority",
        )? != u64::from(family.minimum_literal_bytes)
        || require_u64(
            private_family_authority,
            "maximum_literal_bytes",
            "private family authority",
        )? != u64::from(family.maximum_literal_bytes)
        || require_u64(
            private_family_authority,
            "minimum_window_bytes",
            "private family authority",
        )? != u64::from(family.minimum_window_bytes)
        || require_u64(
            private_family_authority,
            "portable_prefix_candidate_starts",
            "private family authority",
        )? != u64::from(family.portable_prefix_candidate_starts)
    {
        return fail("contract private family envelope differs from authorization");
    }
    let evidence_identity = object(
        required(
            private_family_authority,
            "evidence_identity",
            "private family authority",
        )?,
        "private family evidence identity",
    )?;
    if require_string(
        evidence_identity,
        "algorithm",
        "private family evidence identity",
    )? != "sha256"
    {
        return fail("private family evidence identity algorithm changed");
    }
    let raw_digest_order = array(
        required(
            evidence_identity,
            "raw_digest_order",
            "private family evidence identity",
        )?,
        "private family evidence raw digest order",
    )?;
    let expected_order = [
        "domain_bytes",
        "campaign_contract_sha256",
        "analyzer_source_sha256",
        "discovery_authorization_file_sha256",
    ];
    if raw_digest_order.len() != expected_order.len()
        || raw_digest_order
            .iter()
            .zip(expected_order)
            .any(|(actual, expected)| actual.as_str() != Some(expected))
    {
        return fail("private family evidence raw digest order changed");
    }
    let private_intent_domain = decode_hex_bytes(
        require_string(
            evidence_identity,
            "domain_hex",
            "private family evidence identity",
        )?,
        "contract private intent domain",
    )?;
    if private_intent_domain.is_empty() {
        return fail("contract private intent domain is empty");
    }

    Ok(ContractFacts {
        full_rows,
        static_rows,
        portable_rows,
        long_timing_cells: timed_rows["long-policy"],
        timing_repetitions,
        aggregate_exclusive_maximum,
        stratum_exclusive_maximum,
        cell_inclusive_maximum,
        strict_pair_fraction_minimum,
        private_intent_domain,
    })
}

fn validate_analysis(
    authorization: &Authorization,
    contract: &ContractFacts,
    analysis: &Analysis,
    contract_sha: [u8; 32],
    analysis_sha: [u8; 32],
) -> Result<()> {
    if analysis.schema != authorization.inputs.analysis_schema
        || analysis.contract_sha256 != hex(&contract_sha)
        || analysis.analyzer_source_sha256 != authorization.inputs.analyzer_source_sha256
        || analysis.runner_source_sha256 != authorization.inputs.runner_source_sha256
    {
        return fail("analysis source/contract schema or identity is mixed");
    }
    if analysis.fragment_count != authorization.qualification.required_fragment_count
        || analysis.fragment_sha256s.len()
            != usize::try_from(analysis.fragment_count)
                .map_err(|_| PromotionError::new("fragment count exceeds usize"))?
    {
        return fail("analysis fragment inventory is partial");
    }
    let mut prior = None;
    let mut fragments = BTreeSet::new();
    for digest in &analysis.fragment_sha256s {
        decode_sha256(digest, "fragment SHA-256")?;
        if prior.is_some_and(|value: &String| value >= digest) || !fragments.insert(digest) {
            return fail("analysis fragment SHA-256 inventory is not sorted and unique");
        }
        prior = Some(digest);
    }
    if !analysis.exact_shard_union
        || analysis.overlaps != 0
        || analysis.omissions != 0
        || !analysis.qualification_pass
        || analysis.production_authority_granted
        || analysis.rebar_accepted_as_input
        || analysis.result_derived_exclusions
        || analysis.long_policy_gate_scope != authorization.qualification.long_policy_gate_scope
    {
        return fail("analysis is incomplete, self-authorized, excluded, or Rebar-contaminated");
    }

    let expected_hosts = authorization
        .family
        .targets
        .iter()
        .map(|target| target.host_id.as_str())
        .collect::<BTreeSet<_>>();
    let correctness_hosts = analysis
        .correctness
        .keys()
        .map(String::as_str)
        .collect::<BTreeSet<_>>();
    let timing_hosts = analysis
        .timing
        .keys()
        .map(String::as_str)
        .collect::<BTreeSet<_>>();
    if correctness_hosts != expected_hosts || timing_hosts != expected_hosts {
        return fail("analysis host set is partial, mixed, or untrusted");
    }

    let mut universal_literals = None;
    let mut long_literals = None;
    for host in &expected_hosts {
        let correctness = &analysis.correctness[*host];
        validate_correctness_receipt(
            &correctness.universal,
            contract.full_rows["universal"],
            contract.static_rows["universal"],
            contract.portable_rows["universal"],
            &format!("{host} universal correctness"),
        )?;
        validate_correctness_receipt(
            &correctness.long_policy,
            contract.full_rows["long-policy"],
            contract.static_rows["long-policy"],
            contract.portable_rows["long-policy"],
            &format!("{host} long-policy correctness"),
        )?;
        require_same_nonzero(
            &mut universal_literals,
            correctness.universal.unique_literals,
            "universal unique-literal count",
        )?;
        require_same_nonzero(
            &mut long_literals,
            correctness.long_policy.unique_literals,
            "long-policy unique-literal count",
        )?;
        validate_timing_receipt(
            &analysis.timing[*host].long_policy,
            contract,
            &authorization.qualification.required_strata,
            host,
        )?;
    }

    let analyzer_sha = decode_sha256(
        &authorization.inputs.analyzer_source_sha256,
        "analyzer source SHA-256",
    )?;
    let plan = decode_sha256(&authorization.identities.plan_identity, "plan identity")?;
    let analyzer = decode_sha256(
        &authorization.identities.analyzer_identity,
        "analyzer identity",
    )?;
    let evidence = decode_sha256(
        &authorization.identities.evidence_identity,
        "evidence identity",
    )?;
    if plan != contract_sha || analyzer != analyzer_sha {
        return fail("plan or analyzer identity was not derived from its reviewed source");
    }
    let expected_evidence = evidence_identity(contract_sha, analyzer_sha, analysis_sha);
    if evidence != expected_evidence {
        return fail("evidence identity order, domain, or exact analysis hash changed");
    }
    Ok(())
}

fn validate_correctness_receipt(
    receipt: &CorrectnessReceipt,
    rows: u64,
    static_rows: u64,
    portable_rows: u64,
    label: &str,
) -> Result<()> {
    if !receipt.pass
        || receipt.rows != rows
        || receipt.static_rows != static_rows
        || receipt.portable_rows != portable_rows
        || receipt.static_rows.checked_add(receipt.portable_rows) != Some(receipt.rows)
        || receipt.unique_literals == 0
    {
        return fail(format!("{label} is partial or failed"));
    }
    Ok(())
}

fn validate_timing_receipt(
    receipt: &TimingReceipt,
    contract: &ContractFacts,
    required_strata: &[String],
    host: &str,
) -> Result<()> {
    let expected_pairs = contract
        .long_timing_cells
        .checked_mul(contract.timing_repetitions)
        .ok_or_else(|| PromotionError::new("strict pair count overflow"))?;
    if !receipt.pass
        || receipt.cells != contract.long_timing_cells
        || receipt.strict_pairs != expected_pairs
        || receipt.strict_pair_wins > receipt.strict_pairs
    {
        return fail(format!("{host} timing receipt is partial or failed"));
    }
    let aggregate = ratio(&receipt.aggregate_cell_geomean, "aggregate geomean")?;
    if !aggregate.less_than(
        contract.aggregate_exclusive_maximum,
        "aggregate geomean gate",
    )? {
        return fail(format!("{host} aggregate geomean does not pass"));
    }
    let maximum = ratio(&receipt.maximum_cell_ratio, "maximum cell ratio")?;
    if !maximum.less_than_or_equal(contract.cell_inclusive_maximum, "maximum cell gate")? {
        return fail(format!("{host} maximum cell ratio does not pass"));
    }
    let strict = ratio(
        &receipt.strict_pair_win_fraction,
        "strict pair win fraction",
    )?;
    if receipt.strict_pair_win_fraction.numerator != receipt.strict_pair_wins
        || receipt.strict_pair_win_fraction.denominator != receipt.strict_pairs
        || !strict.greater_than_or_equal(
            contract.strict_pair_fraction_minimum,
            "strict pair fraction gate",
        )?
    {
        return fail(format!("{host} strict pair fraction does not pass"));
    }

    let expected_dimensions = required_strata.iter().collect::<BTreeSet<_>>();
    let observed_dimensions = receipt.strata.keys().collect::<BTreeSet<_>>();
    if expected_dimensions != observed_dimensions {
        return fail(format!(
            "{host} timing stratum dimensions are partial or mixed"
        ));
    }
    for (dimension, entries) in &receipt.strata {
        if entries.is_empty() {
            return fail(format!("{host} timing stratum {dimension:?} is empty"));
        }
        let mut cells = 0_u64;
        for (name, stratum) in entries {
            if name.is_empty() || stratum.cells == 0 {
                return fail(format!("{host} timing stratum entry is empty"));
            }
            cells = cells
                .checked_add(stratum.cells)
                .ok_or_else(|| PromotionError::new("stratum cell count overflow"))?;
            if !ratio(&stratum.geomean, "stratum geomean")?
                .less_than(contract.stratum_exclusive_maximum, "stratum geomean gate")?
            {
                return fail(format!("{host} {dimension} stratum {name:?} does not pass"));
            }
        }
        if cells != receipt.cells {
            return fail(format!(
                "{host} {dimension} stratum cells do not cover the exact matrix"
            ));
        }
    }
    Ok(())
}

fn reconstruct_rows(
    family: &AuthorizedFamily,
    build_tuples: &BTreeMap<String, AuthorizedFamilyTuple>,
    plan_identity: &str,
    analyzer_identity: &str,
    evidence_identity: &str,
) -> Result<Vec<RenderedRow>> {
    if family.wire.backend_version != family.backend_tag {
        return fail("authorized backend tag and wire backend version differ");
    }
    let macos = MacosAarch64ExactSearchManifestV1::<Span>::candidate_backend_tag(
        SearchCompilePolicyV1::high_fuel(),
        family.backend_tag,
    )
    .map_err(|error| PromotionError::new(format!("unsupported macOS backend: {error}")))?;
    let linux = LinuxAarch64ExactSearchManifestV1::<Span>::candidate_backend_tag(
        LinuxAarch64SearchCompilePolicyV1::high_fuel(),
        family.backend_tag,
    )
    .map_err(|error| PromotionError::new(format!("unsupported Linux backend: {error}")))?;
    if macos.backend().backend_version().0 != family.wire.backend_version
        || linux.backend().backend_version().0 != family.wire.backend_version
        || linux.backend().required_features().bits() != family.wire.required_features
    {
        return fail("compiler backend reconstruction differs from authorized wire profile");
    }
    let manifests = BTreeMap::from([
        ("macos", hex(macos.identity().as_bytes())),
        ("linux", hex(linux.identity().as_bytes())),
    ]);
    let mut rows = Vec::with_capacity(family.targets.len());
    for target in &family.targets {
        let tuple = build_tuples
            .get(&target.target_os)
            .ok_or_else(|| PromotionError::new("build receipt family tuple is missing"))?;
        let reconstructed = manifests
            .get(target.target_os.as_str())
            .ok_or_else(|| PromotionError::new("unsupported authorized target OS"))?;
        if reconstructed != &tuple.manifest_identity {
            return fail(format!(
                "{} manifest identity differs from the compiler reconstruction",
                target.host_id
            ));
        }
        rows.push(RenderedRow {
            selector: tuple.family_selector,
            compiler_version: tuple.compiler_version,
            metadata_version: tuple.metadata_version,
            backend_version: tuple.backend_version,
            call_abi_schema: tuple.call_abi_schema,
            exported_symbol_schema: tuple.exported_symbol_schema,
            output_kind: tuple.output_kind,
            architecture: tuple.architecture,
            little_endian: tuple.little_endian,
            pointer_width: tuple.pointer_width,
            target_abi: tuple.target_abi,
            platform: tuple.platform,
            status_bits: tuple.status_bits,
            exported_symbol_n_type: tuple.exported_symbol_n_type,
            required_features: tuple.required_features,
            minimum_literal_bytes: tuple.minimum_literal_bytes,
            maximum_literal_bytes: tuple.maximum_literal_bytes,
            minimum_window_bytes: tuple.minimum_window_bytes,
            portable_prefix_candidate_starts: tuple.portable_prefix_candidate_starts,
            manifest_identity: tuple.manifest_identity.clone(),
            plan_identity: plan_identity.to_owned(),
            analyzer_identity: analyzer_identity.to_owned(),
            evidence_identity: evidence_identity.to_owned(),
            host_id: target.host_id.clone(),
            target_os: target.target_os.clone(),
        });
    }
    rows.sort_by(|left, right| left.target_os.cmp(&right.target_os));
    Ok(rows)
}

fn render_rust(rows: &[RenderedRow], private: bool) -> Vec<u8> {
    let mut output = String::from(
        "// @generated by search-production-family-promotion.\n\
         // Review-only projection: this file is never installed automatically.\n",
    );
    if private {
        output.push_str(
            "use super::{SourceQualifiedStaticSearchSpanFamilyV1, SourceQualifiedStaticSearchSpanRowV1};\n\n\
             /// Exact private rows remain disjoint and empty.\n\
             pub(super) const PRIVATE_QUALIFICATION_STATIC_SEARCH_SPAN_ROWS_V1:\n\
                 &[SourceQualifiedStaticSearchSpanRowV1] = &[];\n\n\
             const _: () = assert!(super::qualification_rows_are_canonical(\n\
                 PRIVATE_QUALIFICATION_STATIC_SEARCH_SPAN_ROWS_V1\n\
             ));\n\n\
             /// Pre-result, intent-authorized private Search-v1 qualification families.\n\
             pub(super) const PRIVATE_QUALIFICATION_STATIC_SEARCH_SPAN_FAMILIES_V1:\n\
                 &[SourceQualifiedStaticSearchSpanFamilyV1] = &[\n",
        );
    } else {
        output.push_str(
            "use super::SourceQualifiedStaticSearchSpanFamilyV1;\n\n\
             /// Artifact-independent, evidence-qualified Search-v1 production families.\n\
             pub(super) const PRODUCTION_SOURCE_QUALIFIED_STATIC_SEARCH_SPAN_FAMILIES_V1:\n\
                 &[SourceQualifiedStaticSearchSpanFamilyV1] = &[\n",
        );
    }
    for row in rows {
        output.push_str(&format!(
            "    #[cfg(all(target_arch = \"aarch64\", target_os = {:?}, target_pointer_width = \"64\", target_endian = \"little\"))]\n",
            row.target_os
        ));
        let constructor = if private {
            "private_qualification"
        } else {
            "production"
        };
        output.push_str(&format!(
            "    SourceQualifiedStaticSearchSpanFamilyV1::{constructor}(\n"
        ));
        for value in [
            u64::from(row.selector),
            u64::from(row.compiler_version),
            u64::from(row.metadata_version),
            u64::from(row.backend_version),
            u64::from(row.call_abi_schema),
            u64::from(row.exported_symbol_schema),
            u64::from(row.output_kind),
            u64::from(row.architecture),
        ] {
            output.push_str(&format!("        {value},\n"));
        }
        output.push_str(&format!("        {},\n", row.little_endian));
        for value in [
            u64::from(row.pointer_width),
            u64::from(row.target_abi),
            u64::from(row.platform),
            u64::from(row.status_bits),
            u64::from(row.exported_symbol_n_type),
            row.required_features,
            u64::from(row.minimum_literal_bytes),
            u64::from(row.maximum_literal_bytes),
            u64::from(row.minimum_window_bytes),
            u64::from(row.portable_prefix_candidate_starts),
        ] {
            output.push_str(&format!("        {value},\n"));
        }
        for identity in [
            &row.manifest_identity,
            &row.plan_identity,
            &row.analyzer_identity,
            &row.evidence_identity,
        ] {
            output.push_str("        ");
            output.push_str(&render_byte_array(identity));
            output.push_str(",\n");
        }
        output.push_str("    ),\n");
    }
    let constant = if private {
        "PRIVATE_QUALIFICATION_STATIC_SEARCH_SPAN_FAMILIES_V1"
    } else {
        "PRODUCTION_SOURCE_QUALIFIED_STATIC_SEARCH_SPAN_FAMILIES_V1"
    };
    output.push_str(&format!(
        "];\n\n\
         const _: () = assert!(super::search_span_families_are_canonical(\n\
             {constant}\n\
         ));\n"
    ));
    output.into_bytes()
}

fn render_byte_array(identity: &str) -> String {
    let bytes = decode_sha256(identity, "rendered identity")
        .expect("validated identities must remain decodable");
    let values = bytes
        .iter()
        .map(|byte| format!("0x{byte:02x}"))
        .collect::<Vec<_>>()
        .join(", ");
    format!("[{values}]")
}

fn evidence_identity(
    contract_sha: [u8; 32],
    analyzer_sha: [u8; 32],
    analysis_sha: [u8; 32],
) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(EVIDENCE_DOMAIN);
    hasher.update(contract_sha);
    hasher.update(analyzer_sha);
    hasher.update(analysis_sha);
    hasher.finalize().into()
}

fn private_intent_identity(
    domain: &[u8],
    contract_sha: [u8; 32],
    analyzer_sha: [u8; 32],
    discovery_authorization_sha: [u8; 32],
) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(domain);
    hasher.update(contract_sha);
    hasher.update(analyzer_sha);
    hasher.update(discovery_authorization_sha);
    hasher.finalize().into()
}

fn ratio(receipt: &RatioReceipt, label: &str) -> Result<Rational> {
    let exact = Rational::new(
        u128::from(receipt.numerator),
        u128::from(receipt.denominator),
        label,
    )?;
    let decimal = decimal_value(&receipt.decimal, &format!("{label} decimal"))?;
    let left = decimal
        .numerator
        .checked_mul(exact.denominator)
        .ok_or_else(|| PromotionError::new(format!("{label} decimal comparison overflow")))?;
    let right = exact
        .numerator
        .checked_mul(decimal.denominator)
        .ok_or_else(|| PromotionError::new(format!("{label} decimal comparison overflow")))?;
    let difference = left.abs_diff(right);
    if difference > exact.denominator {
        return fail(format!(
            "{label} decimal is not a faithful rounded projection"
        ));
    }
    Ok(exact)
}

fn decimal_value(value: &Value, label: &str) -> Result<Rational> {
    let text = match value {
        Value::String(value) => value.as_str(),
        Value::Number(value) => {
            return parse_decimal(&value.to_string(), label);
        }
        _ => return fail(format!("{label} is not a decimal string or number")),
    };
    parse_decimal(text, label)
}

fn parse_decimal(value: &str, label: &str) -> Result<Rational> {
    if value.is_empty()
        || value.starts_with('-')
        || value.starts_with('+')
        || value.contains(['e', 'E'])
    {
        return fail(format!("{label} is not a canonical nonnegative decimal"));
    }
    let mut parts = value.split('.');
    let integer = parts.next().unwrap_or_default();
    let fraction = parts.next();
    if parts.next().is_some()
        || integer.is_empty()
        || !integer.bytes().all(|byte| byte.is_ascii_digit())
        || integer.len() > 1 && integer.starts_with('0')
        || fraction.is_some_and(|digits| {
            digits.is_empty() || !digits.bytes().all(|byte| byte.is_ascii_digit())
        })
    {
        return fail(format!("{label} is not a canonical decimal"));
    }
    let integer_value = integer
        .parse::<u128>()
        .map_err(|_| PromotionError::new(format!("{label} integer overflow")))?;
    let Some(fraction) = fraction else {
        return Rational::new(integer_value, 1, label);
    };
    if fraction.ends_with('0') {
        return fail(format!("{label} has a noncanonical trailing zero"));
    }
    let denominator = 10_u128
        .checked_pow(
            u32::try_from(fraction.len())
                .map_err(|_| PromotionError::new(format!("{label} precision overflow")))?,
        )
        .ok_or_else(|| PromotionError::new(format!("{label} precision overflow")))?;
    let fraction_value = fraction
        .parse::<u128>()
        .map_err(|_| PromotionError::new(format!("{label} fraction overflow")))?;
    let numerator = integer_value
        .checked_mul(denominator)
        .and_then(|value| value.checked_add(fraction_value))
        .ok_or_else(|| PromotionError::new(format!("{label} value overflow")))?;
    Rational::new(numerator, denominator, label)
}

fn validate_ranges(value: &Value, workers: u64, total: u64, label: &str) -> Result<()> {
    let ranges = array(value, label)?;
    if ranges.len()
        != usize::try_from(workers)
            .map_err(|_| PromotionError::new(format!("{label} worker count overflow")))?
    {
        return fail(format!("{label} do not have one interval per worker"));
    }
    let mut cursor = 0_u64;
    for range in ranges {
        let values = array(range, label)?;
        if values.len() != 2 {
            return fail(format!("{label} contain a non-pair interval"));
        }
        let start = values[0]
            .as_u64()
            .ok_or_else(|| PromotionError::new(format!("{label} start is not u64")))?;
        let end = values[1]
            .as_u64()
            .ok_or_else(|| PromotionError::new(format!("{label} end is not u64")))?;
        if start != cursor || end <= start {
            return fail(format!(
                "{label} overlap, omit, or contain an empty interval"
            ));
        }
        cursor = end;
    }
    if cursor != total {
        return fail(format!("{label} do not cover the exact projection"));
    }
    Ok(())
}

fn require_same_nonzero(slot: &mut Option<u64>, value: u64, label: &str) -> Result<()> {
    if value == 0 || slot.is_some_and(|expected| expected != value) {
        return fail(format!("{label} differs across hosts or is zero"));
    }
    *slot = Some(value);
    Ok(())
}

fn parse_json<T: for<'de> Deserialize<'de>>(bytes: &[u8], label: &str) -> Result<T> {
    let mut deserializer = serde_json::Deserializer::from_slice(bytes);
    let value = T::deserialize(&mut deserializer)
        .map_err(|error| PromotionError::new(format!("{label} is invalid JSON: {error}")))?;
    deserializer
        .end()
        .map_err(|error| PromotionError::new(format!("{label} has trailing data: {error}")))?;
    Ok(value)
}

fn canonical_json(value: &Value) -> Result<Vec<u8>> {
    let mut bytes = serde_json::to_vec(value)
        .map_err(|error| PromotionError::new(format!("canonical JSON failed: {error}")))?;
    bytes.push(b'\n');
    Ok(bytes)
}

fn object<'a>(value: &'a Value, label: &str) -> Result<&'a Map<String, Value>> {
    value
        .as_object()
        .ok_or_else(|| PromotionError::new(format!("{label} is not an object")))
}

fn array<'a>(value: &'a Value, label: &str) -> Result<&'a Vec<Value>> {
    value
        .as_array()
        .ok_or_else(|| PromotionError::new(format!("{label} is not an array")))
}

fn required<'a>(object: &'a Map<String, Value>, key: &str, label: &str) -> Result<&'a Value> {
    object
        .get(key)
        .ok_or_else(|| PromotionError::new(format!("{label} lacks {key:?}")))
}

fn require_string<'a>(object: &'a Map<String, Value>, key: &str, label: &str) -> Result<&'a str> {
    required(object, key, label)?
        .as_str()
        .ok_or_else(|| PromotionError::new(format!("{label}.{key} is not a string")))
}

fn require_u64(object: &Map<String, Value>, key: &str, label: &str) -> Result<u64> {
    required(object, key, label)?
        .as_u64()
        .ok_or_else(|| PromotionError::new(format!("{label}.{key} is not u64")))
}

fn require_bool(object: &Map<String, Value>, key: &str, label: &str, expected: bool) -> Result<()> {
    if required(object, key, label)?.as_bool() != Some(expected) {
        return fail(format!("{label}.{key} is not {expected}"));
    }
    Ok(())
}

fn require_empty_array(object: &Map<String, Value>, key: &str, label: &str) -> Result<()> {
    if !array(required(object, key, label)?, &format!("{label}.{key}"))?.is_empty() {
        return fail(format!("{label}.{key} is not empty"));
    }
    Ok(())
}

fn require_hex_field(object: &Map<String, Value>, key: &str, label: &str) -> Result<()> {
    decode_sha256(
        require_string(object, key, label)?,
        &format!("{label}.{key}"),
    )?;
    Ok(())
}

fn decode_sha256(value: &str, label: &str) -> Result<[u8; 32]> {
    if value.len() != 64 {
        return fail(format!("{label} is not canonical lowercase SHA-256"));
    }
    let bytes = decode_hex_bytes(value, label)?;
    bytes
        .try_into()
        .map_err(|_| PromotionError::new(format!("{label} is not SHA-256")))
}

fn decode_hex_bytes(value: &str, label: &str) -> Result<Vec<u8>> {
    if value.len() % 2 != 0
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase())
    {
        return fail(format!("{label} is not canonical lowercase hexadecimal"));
    }
    let mut output = vec![0_u8; value.len() / 2];
    for (index, slot) in output.iter_mut().enumerate() {
        let offset = index
            .checked_mul(2)
            .ok_or_else(|| PromotionError::new("hex offset overflow"))?;
        *slot = u8::from_str_radix(&value[offset..offset + 2], 16)
            .map_err(|_| PromotionError::new(format!("{label} is malformed")))?;
    }
    Ok(output)
}

fn sha256(bytes: &[u8]) -> [u8; 32] {
    Sha256::digest(bytes).into()
}

fn require_digest(bytes: &[u8], expected: [u8; 32], label: &str) -> Result<()> {
    if sha256(bytes) != expected {
        return fail(format!("{label} SHA-256 differs from authority"));
    }
    Ok(())
}

fn hex(bytes: &[u8]) -> String {
    let mut output = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        use fmt::Write as _;
        write!(output, "{byte:02x}").expect("String formatting is infallible");
    }
    output
}

#[cfg(unix)]
fn read_bounded_regular(path: &Path, maximum: u64) -> Result<Vec<u8>> {
    let mut options = OpenOptions::new();
    options
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC);
    let mut file = options
        .open(path)
        .map_err(|error| PromotionError::new(format!("cannot open {}: {error}", path.display())))?;
    let before = file
        .metadata()
        .map_err(|error| PromotionError::new(format!("cannot stat {}: {error}", path.display())))?;
    if !before.file_type().is_file()
        || before.len() > maximum
        || before.nlink() != 1
        || before.mode() & 0o022 != 0
    {
        return fail(format!(
            "{} is not one bounded, non-shared, non-group-writable regular file",
            path.display()
        ));
    }
    let capacity = usize::try_from(before.len())
        .map_err(|_| PromotionError::new("input length exceeds usize"))?;
    let mut bytes = Vec::with_capacity(capacity);
    file.read_to_end(&mut bytes)
        .map_err(|error| PromotionError::new(format!("cannot read {}: {error}", path.display())))?;
    let after = file.metadata().map_err(|error| {
        PromotionError::new(format!("cannot restat {}: {error}", path.display()))
    })?;
    if before.dev() != after.dev()
        || before.ino() != after.ino()
        || before.len() != after.len()
        || u64::try_from(bytes.len()).ok() != Some(before.len())
    {
        return fail(format!("{} changed while being read", path.display()));
    }
    Ok(bytes)
}

#[cfg(not(unix))]
fn read_bounded_regular(_path: &Path, _maximum: u64) -> Result<Vec<u8>> {
    fail("the promotion transaction requires Unix O_NOFOLLOW")
}

#[cfg(unix)]
fn write_transaction(path: &Path, generated: &GeneratedTransaction) -> Result<()> {
    if path.as_os_str().is_empty() || path.parent().is_none() {
        return fail("output directory path is not explicit");
    }
    fs::create_dir(path).map_err(|error| {
        PromotionError::new(format!(
            "cannot create fresh output directory {}: {error}",
            path.display()
        ))
    })?;
    fs::set_permissions(path, fs::Permissions::from_mode(0o700)).map_err(|error| {
        PromotionError::new(format!(
            "cannot secure output directory {}: {error}",
            path.display()
        ))
    })?;
    write_create_only(path.join(generated.source_basename), &generated.rust)?;
    write_create_only(path.join(OUTPUT_RECEIPT), &generated.receipt)?;
    write_create_only(path.join(OUTPUT_SHA256SUMS), &generated.sha256sums)?;
    // This marker is deliberately last.  A partial directory has no commit.
    write_create_only(path.join(OUTPUT_COMMITTED), &generated.committed)?;
    File::open(path)
        .and_then(|directory| directory.sync_all())
        .map_err(|error| PromotionError::new(format!("cannot sync {}: {error}", path.display())))?;
    Ok(())
}

#[cfg(not(unix))]
fn write_transaction(_path: &Path, _generated: &GeneratedTransaction) -> Result<()> {
    fail("the promotion transaction requires Unix create-only output")
}

#[cfg(unix)]
fn write_create_only(path: PathBuf, bytes: &[u8]) -> Result<()> {
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(&path)
        .map_err(|error| {
            PromotionError::new(format!("cannot create {}: {error}", path.display()))
        })?;
    file.write_all(bytes)
        .and_then(|()| file.sync_all())
        .map_err(|error| PromotionError::new(format!("cannot seal {}: {error}", path.display())))?;
    fs::set_permissions(&path, fs::Permissions::from_mode(0o400)).map_err(|error| {
        PromotionError::new(format!("cannot make {} read-only: {error}", path.display()))
    })?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    const CONTRACT_SCHEMA: &str = "fre.test.search-campaign-contract.v1";
    const ANALYSIS_SCHEMA: &str = "fre.aot.search-tag30-qualification-analysis.v1";
    const MAC_HOST: &str = "synthetic-apple-aarch64-asimd";
    const LINUX_HOST: &str = "synthetic-linux-aarch64-asimd";
    const PRIVATE_DOMAIN: &[u8] = b"FRE-TEST-PRE-RESULT-CAMPAIGN-INTENT\0\x01";

    struct PrivateFixture {
        contract: Vec<u8>,
        authorization: Value,
        discovery_receipts: Vec<Vec<u8>>,
    }

    impl PrivateFixture {
        fn new() -> Self {
            let contract = json_bytes(&contract_value(PRIVATE_DOMAIN));
            let discovery_receipts = synthetic_discovery_receipts(&contract);
            let authorization =
                private_authorization(&contract, private_family(&discovery_receipts));
            Self {
                contract,
                authorization,
                discovery_receipts,
            }
        }

        fn authorization_bytes(&self) -> Vec<u8> {
            json_bytes(&self.authorization)
        }

        fn render(&self) -> Result<GeneratedTransaction> {
            let authorization = self.authorization_bytes();
            generate_private_transaction(
                &authorization,
                sha256(&authorization),
                &self.contract,
                &self.discovery_receipts,
            )
        }
    }

    fn json_bytes(value: &Value) -> Vec<u8> {
        serde_json::to_vec(value).expect("synthetic JSON")
    }

    fn digest_text(label: &[u8]) -> String {
        hex(&sha256(label))
    }

    fn manifest_identity(target_os: &str) -> String {
        match target_os {
            "macos" => hex(
                MacosAarch64ExactSearchManifestV1::<Span>::candidate_backend_tag(
                    SearchCompilePolicyV1::high_fuel(),
                    30,
                )
                .expect("synthetic macOS manifest")
                .identity()
                .as_bytes(),
            ),
            "linux" => hex(
                LinuxAarch64ExactSearchManifestV1::<Span>::candidate_backend_tag(
                    LinuxAarch64SearchCompilePolicyV1::high_fuel(),
                    30,
                )
                .expect("synthetic Linux manifest")
                .identity()
                .as_bytes(),
            ),
            _ => panic!("unsupported synthetic target"),
        }
    }

    fn tuple_value(target_os: &str) -> Value {
        let (platform, exported_symbol_n_type) = match target_os {
            "macos" => (SEARCH_PLATFORM_MACOS_V1, SEARCH_EXPORTED_SYMBOL_N_TYPE_V1),
            "linux" => (
                SEARCH_PLATFORM_LINUX_V1,
                SEARCH_EXPORTED_SYMBOL_INFO_ELF_FUNCTION_V1,
            ),
            _ => panic!("unsupported synthetic target"),
        };
        json!({
            "compiler_version": AOT_SEARCH_COMPILER_VERSION_V1,
            "metadata_version": SEARCH_METADATA_VERSION_V1,
            "backend_version": 30,
            "call_abi_schema": SEARCH_CALL_ABI_SCHEMA_V1,
            "exported_symbol_schema": SEARCH_EXPORTED_SYMBOL_SCHEMA_VERSION_V1,
            "output_kind": SEARCH_SPAN_OUTPUT_KIND_V1,
            "architecture": SEARCH_ARCHITECTURE_AARCH64_V1,
            "little_endian": true,
            "pointer_width": SEARCH_POINTER_WIDTH_V1,
            "target_abi": SEARCH_TARGET_ABI_AAPCS64_V1,
            "platform": platform,
            "status_bits": SEARCH_STATUS_BITS_V1,
            "exported_symbol_n_type": exported_symbol_n_type,
            "required_features": SEARCH_REQUIRED_ASIMD_FEATURES_V1,
            "manifest_identity": manifest_identity(target_os),
            "family_selector": 13,
            "minimum_literal_bytes": 6,
            "maximum_literal_bytes": 32,
            "minimum_window_bytes": 65_536,
            "portable_prefix_candidate_starts": 256,
        })
    }

    fn target_value(target_os: &str, build_receipt: Option<&[u8]>, discovery: bool) -> Value {
        let host_id = match target_os {
            "macos" => MAC_HOST,
            "linux" => LINUX_HOST,
            _ => panic!("unsupported synthetic target"),
        };
        let mut target = json!({
            "host_id": host_id,
            "target_os": target_os,
            "target_arch": "aarch64",
            "asimd": true,
            "family_tuple": tuple_value(target_os),
        });
        if let Some(receipt) = build_receipt {
            if discovery {
                target["discovery_build_receipt_schema"] = json!(BUILD_RECEIPT_SCHEMA);
                target["discovery_build_receipt_sha256"] = json!(hex(&sha256(receipt)));
            } else {
                target["build_receipt_schema"] = json!(BUILD_RECEIPT_SCHEMA);
                target["build_receipt_sha256"] = json!(hex(&sha256(receipt)));
            }
        }
        target
    }

    fn family_value(build_receipts: Option<&[Vec<u8>]>, discovery: bool) -> Value {
        let (mac_receipt, linux_receipt) = match build_receipts {
            Some(receipts) => {
                assert_eq!(receipts.len(), 2);
                (Some(receipts[0].as_slice()), Some(receipts[1].as_slice()))
            }
            None => (None, None),
        };
        json!({
            "selector": 13,
            "backend_tag": 30,
            "backend_name": "AsimdV17",
            "backend_version": "SEARCH_V17",
            "candidate_policy": 15,
            "aot_magic_hex": TAG30_AOT_MAGIC_HEX,
            "compiler_profile": COMPILER_PROFILE,
            "minimum_literal_bytes": 6,
            "maximum_literal_bytes": 32,
            "minimum_window_bytes": 65_536,
            "portable_prefix_candidate_starts": 256,
            "wire": {
                "compiler_version": AOT_SEARCH_COMPILER_VERSION_V1,
                "metadata_version": SEARCH_METADATA_VERSION_V1,
                "backend_version": 30,
                "call_abi_schema": SEARCH_CALL_ABI_SCHEMA_V1,
                "exported_symbol_schema": SEARCH_EXPORTED_SYMBOL_SCHEMA_VERSION_V1,
                "output_kind": SEARCH_SPAN_OUTPUT_KIND_V1,
                "architecture": SEARCH_ARCHITECTURE_AARCH64_V1,
                "little_endian": true,
                "pointer_width": SEARCH_POINTER_WIDTH_V1,
                "target_abi": SEARCH_TARGET_ABI_AAPCS64_V1,
                "status_bits": SEARCH_STATUS_BITS_V1,
                "required_features": SEARCH_REQUIRED_ASIMD_FEATURES_V1,
            },
            "targets": [
                target_value("macos", mac_receipt, discovery),
                target_value("linux", linux_receipt, discovery),
            ],
        })
    }

    fn private_family(discovery_receipts: &[Vec<u8>]) -> Value {
        family_value(Some(discovery_receipts), true)
    }

    fn contract_value(private_domain: &[u8]) -> Value {
        let projection = |timed_rows| {
            json!({
                "full_rows": 4,
                "correctness_static_rows": 2,
                "correctness_portable_rows": 2,
                "full_sha256": digest_text(b"synthetic-full-projection"),
                "timed_sha256": digest_text(b"synthetic-timed-projection"),
                "timed_rows": timed_rows,
                "production_input_floor_bytes": 65_536,
            })
        };
        json!({
            "schema": CONTRACT_SCHEMA,
            "result_blind": true,
            "rebar_inputs": [],
            "result_derived_selection": false,
            "result_derived_exclusions": false,
            "backend": {
                "tag": 30,
                "name": "AsimdV17",
                "version": "SEARCH_V17",
                "candidate_policy": 15,
                "aot_magic_hex": TAG30_AOT_MAGIC_HEX,
                "llvm": false,
            },
            "hosts": [
                {
                    "id": MAC_HOST,
                    "target_os": "macos",
                    "target_arch": "aarch64",
                    "asimd": true,
                },
                {
                    "id": LINUX_HOST,
                    "target_os": "linux",
                    "target_arch": "aarch64",
                    "asimd": true,
                },
            ],
            "projections": {
                "universal": projection(2),
                "long-policy": projection(2),
            },
            "sharding": {
                "shards": 2,
                "concurrent_workers": 2,
                "correctness_ranges": [[0, 2], [2, 4]],
                "universal_timing_ranges": [[0, 1], [1, 2]],
                "long_policy_timing_ranges": [[0, 1], [1, 2]],
            },
            "long_policy_gates": {
                "one_failure_rejects_whole_class": true,
                "result_derived_exclusions": false,
                "aggregate_candidate_over_portable_exclusive_maximum": "1",
                "each_width_geomean_exclusive_maximum": "1",
                "each_topology_geomean_exclusive_maximum": "1",
                "each_window_geomean_exclusive_maximum": "1",
                "each_outcome_geomean_exclusive_maximum": "1",
                "each_learned_source_kind_geomean_exclusive_maximum": "1",
                "individual_cell_inclusive_maximum": "2",
                "strict_pair_win_fraction_minimum": "0.5",
                "timing_repetitions": 2,
            },
            "private_family_authority": {
                "evidence_identity": {
                    "algorithm": "sha256",
                    "domain_hex": hex(private_domain),
                    "raw_digest_order": [
                        "domain_bytes",
                        "campaign_contract_sha256",
                        "analyzer_source_sha256",
                        "discovery_authorization_file_sha256",
                    ],
                },
                "family_selector": 13,
                "minimum_literal_bytes": 6,
                "maximum_literal_bytes": 32,
                "minimum_window_bytes": 65_536,
                "portable_prefix_candidate_starts": 256,
            },
        })
    }

    fn qualification_value() -> Value {
        json!({
            "required_fragment_count": 4,
            "required_strata": ["width", "topology"],
            "long_policy_gate_scope": {
                "scope": "synthetic-universal-and-long",
            },
        })
    }

    fn private_authorization(contract: &[u8], family: Value) -> Value {
        let target = |index: usize| {
            let target = &family["targets"][index];
            json!({
                "host_id": target["host_id"],
                "target_os": target["target_os"],
                "target_arch": target["target_arch"],
                "manifest_identity": target["family_tuple"]["manifest_identity"],
                "discovery_build_receipt_schema":
                    target["discovery_build_receipt_schema"],
                "discovery_build_receipt_sha256":
                    target["discovery_build_receipt_sha256"],
                "family_tuple": target["family_tuple"],
            })
        };
        let payload = json!({
            "contract_schema": CONTRACT_SCHEMA,
            "campaign_contract_sha256": hex(&sha256(contract)),
            "analyzer_source_sha256": digest_text(b"synthetic-analyzer-source"),
            "prepared_inputs_sha256": digest_text(b"synthetic-prepared-inputs"),
            "object_candidate_manifest_schema": "fre.test.object-candidates.v1",
            "object_candidate_manifest_sha256":
                digest_text(b"synthetic-object-candidates"),
            "object_candidate_manifest_payload_sha256":
                digest_text(b"synthetic-object-candidate-payload"),
            "literal_dispositions_schema": "fre.test.literal-dispositions.v1",
            "literal_dispositions_sha256":
                digest_text(b"synthetic-literal-dispositions"),
            "literal_dispositions_payload_sha256":
                digest_text(b"synthetic-literal-disposition-payload"),
            "prepare_source_sha256": digest_text(b"synthetic-prepare-source"),
            "discovery_runner_revision": "0123456789abcdef0123456789abcdef01234567",
            "discovery_runner_source_sha256": digest_text(b"synthetic-runner-source"),
            "discovery_source_archive_sha256": digest_text(b"synthetic-source-archive"),
            "discovery_identity_sha256": digest_text(b"synthetic-discovery-identity"),
            "discovery_private_family_source_sha256":
                digest_text(b"synthetic-private-empty-source"),
            "family_common": {
                "backend": {
                    "name": family["backend_name"],
                    "tag": family["backend_tag"],
                    "version": family["backend_version"],
                    "candidate_policy": family["candidate_policy"],
                    "llvm": false,
                },
                "compiler": {
                    "identity": digest_text(b"synthetic-compiler-identity"),
                },
                "wire": {
                    "aot_magic_hex": TAG30_AOT_MAGIC_HEX,
                    "static_abi": STATIC_ABI_SCHEMA,
                    "output": OUTPUT_TYPE,
                    "link_interface_schema": LINK_INTERFACE_SCHEMA,
                },
                "envelope": {
                    "family_selector": family["selector"],
                    "minimum_literal_bytes": family["minimum_literal_bytes"],
                    "maximum_literal_bytes": family["maximum_literal_bytes"],
                    "minimum_window_bytes": family["minimum_window_bytes"],
                    "portable_prefix_candidate_starts":
                        family["portable_prefix_candidate_starts"],
                },
            },
            "decision": {
                "private_projection": true,
                "production_projection": false,
                "pre_result_intent": true,
                "analyzer_not_deployment_authority": true,
                "targets_one_class": true,
                "rebar_permitted": false,
                "result_derived_exclusions": false,
            },
            "qualification": qualification_value(),
            "targets": {
                "macos_aarch64": target(0),
                "linux_aarch64": target(1),
            },
        });
        json!({
            "schema": PRIVATE_AUTHORIZATION_SCHEMA,
            "payload_sha256": hex(&sha256(&json_bytes(&payload))),
            "payload": payload,
        })
    }

    fn reseal_private_payload(authorization: &mut Value) {
        authorization["payload_sha256"] =
            json!(hex(&sha256(&json_bytes(&authorization["payload"]))));
    }

    fn production_authorization(contract: &[u8], family: Value) -> Value {
        json!({
            "schema": AUTHORIZATION_SCHEMA,
            "decision": {
                "production_source_projection_authorized": true,
                "analyzer_is_not_deployment_authority": true,
                "targets_reviewed_as_one_class": true,
                "rebar_accepted_as_input": false,
                "result_derived_exclusions_authorized": false,
            },
            "inputs": {
                "contract_schema": CONTRACT_SCHEMA,
                "contract_sha256": hex(&sha256(contract)),
                "analysis_schema": ANALYSIS_SCHEMA,
                "analysis_sha256": digest_text(b"synthetic-analysis"),
                "analyzer_source_sha256": digest_text(b"synthetic-analyzer-source"),
                "runner_source_sha256": digest_text(b"synthetic-runner-source"),
            },
            "family": family,
            "identities": {
                "evidence_domain_hex": hex(EVIDENCE_DOMAIN),
                "plan_identity": hex(&sha256(contract)),
                "analyzer_identity": digest_text(b"synthetic-analyzer-source"),
                "evidence_identity": digest_text(b"synthetic-evidence"),
            },
            "qualification": qualification_value(),
        })
    }

    fn build_receipt(
        target_os: &str,
        plan: &str,
        analyzer: &str,
        evidence: &str,
        tuple: Value,
    ) -> Vec<u8> {
        let host_id = match target_os {
            "macos" => MAC_HOST,
            "linux" => LINUX_HOST,
            _ => panic!("unsupported synthetic target"),
        };
        json_bytes(&json!({
            "schema": BUILD_RECEIPT_SCHEMA,
            "host_id": host_id,
            "target_os": target_os,
            "target_arch": "aarch64",
            "runner_source_sha256": digest_text(b"synthetic-runner-source"),
            "plan_identity": plan,
            "analyzer_identity": analyzer,
            "evidence_identity": evidence,
            "family_tuple": tuple,
        }))
    }

    fn valid_build_receipt_parts() -> (
        AuthorizedFamily,
        String,
        String,
        String,
        String,
        Vec<Vec<u8>>,
    ) {
        let plan = digest_text(b"synthetic-plan");
        let analyzer = digest_text(b"synthetic-analyzer-source");
        let evidence = digest_text(b"synthetic-evidence");
        let runner = digest_text(b"synthetic-runner-source");
        let receipts = vec![
            build_receipt("macos", &plan, &analyzer, &evidence, tuple_value("macos")),
            build_receipt("linux", &plan, &analyzer, &evidence, tuple_value("linux")),
        ];
        let family =
            serde_json::from_value(family_value(Some(&receipts), false)).expect("synthetic family");
        (family, runner, plan, analyzer, evidence, receipts)
    }

    fn synthetic_discovery_receipts(contract: &[u8]) -> Vec<Vec<u8>> {
        let plan = hex(&sha256(contract));
        let analyzer = digest_text(b"synthetic-analyzer-source");
        vec![
            discovery_build_receipt("macos", &plan, &analyzer, tuple_value("macos")),
            discovery_build_receipt("linux", &plan, &analyzer, tuple_value("linux")),
        ]
    }

    fn discovery_build_receipt(
        target_os: &str,
        plan: &str,
        analyzer: &str,
        tuple: Value,
    ) -> Vec<u8> {
        let host_id = match target_os {
            "macos" => MAC_HOST,
            "linux" => LINUX_HOST,
            _ => panic!("unsupported synthetic target"),
        };
        let candidate_literal = b"abcdef";
        let refusal_literal = b"ghij";
        json_bytes(&json!({
            "schema": BUILD_RECEIPT_SCHEMA,
            "identity_sha256": digest_text(b"synthetic-discovery-identity"),
            "runner_revision": "0123456789abcdef0123456789abcdef01234567",
            "runner_source_sha256": digest_text(b"synthetic-runner-source"),
            "source_archive_sha256": digest_text(b"synthetic-source-archive"),
            "private_family_source_sha256": digest_text(b"synthetic-private-empty-source"),
            "target_os": target_os,
            "target_arch": "aarch64",
            "host_id": host_id,
            "backend_name": "AsimdV17",
            "backend_tag": 30,
            "backend_version": "SEARCH_V17",
            "candidate_policy": 15,
            "llvm": false,
            "compiler_identity": digest_text(b"synthetic-compiler-identity"),
            "manifest_identity": tuple["manifest_identity"],
            "discovery_authorization_sha256": null,
            "discovery_build_receipt_sha256": null,
            "family_selector": 13,
            "minimum_literal_bytes": 6,
            "maximum_literal_bytes": 32,
            "minimum_window_bytes": 65_536,
            "portable_prefix_candidate_starts": 256,
            "family_tuple": tuple,
            "plan_identity": plan,
            "analyzer_identity": analyzer,
            "evidence_identity": null,
            "timing_permitted": false,
            "object_candidate_manifest_schema": "fre.test.object-candidates.v1",
            "object_candidate_manifest_sha256":
                digest_text(b"synthetic-object-candidates"),
            "object_candidate_manifest_payload_sha256":
                digest_text(b"synthetic-object-candidate-payload"),
            "object_candidate_count": 1,
            "literal_dispositions_sha256":
                digest_text(b"synthetic-literal-dispositions"),
            "literal_dispositions_payload_sha256":
                digest_text(b"synthetic-literal-disposition-payload"),
            "literal_disposition_count": 2,
            "prepared_inputs_sha256": digest_text(b"synthetic-prepared-inputs"),
            "prepare_source_sha256": digest_text(b"synthetic-prepare-source"),
            "canonical_byte_escaped_sources": true,
            "candidates": [{
                "ordinal": 0,
                "semantic_candidate_sha256": digest_text(b"synthetic-candidate-semantic"),
                "literal_sha256": hex(&sha256(candidate_literal)),
                "literal_hex": hex(candidate_literal),
                "compile_identity": digest_text(b"synthetic-compile-identity"),
                "compile_receipt_sha256": digest_text(b"synthetic-compile-receipt"),
                "compile_receipt_basename": "compile-receipt.json",
                "implementation_object_sha256": digest_text(b"synthetic-implementation-object"),
                "glue_object_sha256": digest_text(b"synthetic-glue-object"),
                "implementation_object_basename": "implementation.o",
                "glue_object_basename": "glue.o",
                "implementation_symbols": {
                    "entry": "fre_entry",
                    "payload": "fre_payload",
                    "metadata": "fre_metadata",
                },
                "glue_symbol": "fre_glue",
            }],
            "refusals": [{
                "ordinal": 0,
                "semantic_candidate_sha256": digest_text(b"synthetic-refusal-semantic"),
                "literal_sha256": hex(&sha256(refusal_literal)),
                "literal_hex": hex(refusal_literal),
                "disposition": "structural-refusal",
                "compile_receipt_sha256": digest_text(b"synthetic-refusal-receipt"),
                "compile_receipt_basename": "refusal-receipt.json",
            }],
        }))
    }

    #[test]
    fn private_mode_renders_complete_private_only_source() {
        let fixture = PrivateFixture::new();
        let generated = fixture.render().expect("valid private transaction");
        let source = String::from_utf8(generated.rust).expect("generated UTF-8");
        assert_eq!(generated.source_basename, PRIVATE_OUTPUT_RUST);
        assert!(source.contains("PRIVATE_QUALIFICATION_STATIC_SEARCH_SPAN_ROWS_V1"));
        assert!(source.contains("PRIVATE_QUALIFICATION_STATIC_SEARCH_SPAN_FAMILIES_V1"));
        assert!(source.contains("SourceQualifiedStaticSearchSpanFamilyV1::private_qualification"));
        assert!(source.contains("target_os = \"macos\""));
        assert!(source.contains("target_os = \"linux\""));
        assert!(source.contains("target_pointer_width = \"64\""));
        assert!(source.contains("target_endian = \"little\""));
        assert!(!source.contains("::production("));

        let receipt: Value = serde_json::from_slice(&generated.receipt).expect("receipt JSON");
        let authorization = fixture.authorization_bytes();
        let expected = private_intent_identity(
            PRIVATE_DOMAIN,
            sha256(&fixture.contract),
            sha256(b"synthetic-analyzer-source"),
            sha256(&authorization),
        );
        assert_eq!(
            receipt["intent_derivation"]["intent_evidence_identity"],
            hex(&expected)
        );
    }

    #[test]
    fn production_and_private_authority_schemas_cannot_be_confused() {
        let fixture = PrivateFixture::new();
        let private = fixture.authorization_bytes();
        let production_family = {
            let (family, _, _, _, _, _) = valid_build_receipt_parts();
            serde_json::to_value(family).expect("family JSON")
        };
        let production = json_bytes(&production_authorization(
            &fixture.contract,
            production_family,
        ));
        assert!(
            generate_transaction(&private, sha256(&private), &fixture.contract, b"{}", &[],)
                .is_err()
        );
        assert!(
            generate_private_transaction(
                &production,
                sha256(&production),
                &fixture.contract,
                &fixture.discovery_receipts,
            )
            .is_err()
        );
    }

    #[test]
    fn production_rendering_is_sealed_without_external_application_and_heldout_gates() {
        let fixture = PrivateFixture::new();
        let (family, _, _, _, _, _) = valid_build_receipt_parts();
        let authorization = json_bytes(&production_authorization(
            &fixture.contract,
            serde_json::to_value(family).expect("family JSON"),
        ));
        let error = generate_transaction(
            &authorization,
            sha256(&authorization),
            &fixture.contract,
            b"{}",
            &[],
        )
        .expect_err("synthetic-only production must remain sealed");
        assert!(error.to_string().contains("independent application"));
        assert!(error.to_string().contains("external-regex heldout"));
    }

    #[test]
    fn private_authority_refuses_the_post_render_build_receipt_cycle() {
        let fixture = PrivateFixture::new();
        let mut authorization = fixture.authorization.clone();
        authorization["payload"]["targets"]["macos_aarch64"]["build_receipt_schema"] =
            json!(BUILD_RECEIPT_SCHEMA);
        authorization["payload"]["targets"]["macos_aarch64"]["build_receipt_sha256"] =
            json!(digest_text(b"synthetic-post-render-receipt"));
        reseal_private_payload(&mut authorization);
        let authorization = json_bytes(&authorization);
        let error = generate_private_transaction(
            &authorization,
            sha256(&authorization),
            &fixture.contract,
            &fixture.discovery_receipts,
        )
        .expect_err("private authority must not pin post-render build receipts");
        assert!(
            error
                .to_string()
                .contains("unknown field `build_receipt_schema`")
        );
    }

    #[test]
    fn private_intent_domain_comes_from_the_exact_contract() {
        let fixture = PrivateFixture::new();
        let mut changed_contract: Value =
            serde_json::from_slice(&fixture.contract).expect("contract JSON");
        changed_contract["private_family_authority"]["evidence_identity"]["domain_hex"] =
            json!(hex(b"FRE-DIFFERENT-PRIVATE-DOMAIN\0\x01"));
        let changed_contract = json_bytes(&changed_contract);
        let discovery_receipts = synthetic_discovery_receipts(&changed_contract);
        let authorization = json_bytes(&private_authorization(
            &changed_contract,
            private_family(&discovery_receipts),
        ));
        let generated = generate_private_transaction(
            &authorization,
            sha256(&authorization),
            &changed_contract,
            &discovery_receipts,
        )
        .expect("contract-declared domain must be authoritative");
        let receipt: Value =
            serde_json::from_slice(&generated.receipt).expect("private receipt JSON");
        let expected = private_intent_identity(
            b"FRE-DIFFERENT-PRIVATE-DOMAIN\0\x01",
            sha256(&changed_contract),
            sha256(b"synthetic-analyzer-source"),
            sha256(&authorization),
        );
        assert_eq!(
            receipt["intent_derivation"]["intent_evidence_identity"],
            hex(&expected)
        );
    }

    #[test]
    fn private_authorization_is_externally_sha_pinned() {
        let fixture = PrivateFixture::new();
        let authorization = fixture.authorization_bytes();
        let error = generate_private_transaction(
            &authorization,
            [0_u8; 32],
            &fixture.contract,
            &fixture.discovery_receipts,
        )
        .expect_err("wrong external authorization hash");
        assert!(error.to_string().contains("SHA-256 differs from authority"));
    }

    #[test]
    fn exact_contract_private_family_envelope_is_required_field_by_field() {
        let fixture = PrivateFixture::new();
        for (field, changed) in [
            ("family_selector", json!(14)),
            ("minimum_literal_bytes", json!(7)),
            ("maximum_literal_bytes", json!(31)),
            ("minimum_window_bytes", json!(65_535)),
            ("portable_prefix_candidate_starts", json!(255)),
        ] {
            let mut contract: Value =
                serde_json::from_slice(&fixture.contract).expect("contract JSON");
            contract["private_family_authority"][field] = changed;
            let contract = json_bytes(&contract);
            let discovery_receipts = synthetic_discovery_receipts(&contract);
            let authorization = json_bytes(&private_authorization(
                &contract,
                private_family(&discovery_receipts),
            ));
            let error = generate_private_transaction(
                &authorization,
                sha256(&authorization),
                &contract,
                &discovery_receipts,
            )
            .expect_err("contract envelope drift must fail");
            assert!(
                error
                    .to_string()
                    .contains("contract private family envelope"),
                "{field} produced unexpected refusal: {error}"
            );
        }
    }

    #[test]
    fn private_discovery_receipts_are_exact_complete_and_sha_pinned() {
        let fixture = PrivateFixture::new();
        let authorization = fixture.authorization_bytes();
        let partial = fixture.discovery_receipts[..1].to_vec();
        let error = generate_private_transaction(
            &authorization,
            sha256(&authorization),
            &fixture.contract,
            &partial,
        )
        .expect_err("partial discovery receipt set");
        assert!(error.to_string().contains("partial"));

        let mut corrupted = fixture.discovery_receipts;
        corrupted[1].push(b' ');
        let error = generate_private_transaction(
            &authorization,
            sha256(&authorization),
            &fixture.contract,
            &corrupted,
        )
        .expect_err("mutated discovery receipt bytes");
        assert!(
            error
                .to_string()
                .contains("differ from reviewed authorization")
        );
    }

    #[test]
    fn target_common_tuple_drift_and_manifest_drift_fail_closed() {
        let fixture = PrivateFixture::new();
        let mut common_drift = fixture.authorization.clone();
        common_drift["payload"]["targets"]["linux_aarch64"]["family_tuple"]["pointer_width"] =
            json!(32);
        reseal_private_payload(&mut common_drift);
        let common_drift = json_bytes(&common_drift);
        let common_error = generate_private_transaction(
            &common_drift,
            sha256(&common_drift),
            &fixture.contract,
            &fixture.discovery_receipts,
        )
        .expect_err("common tuple drift");
        assert!(
            common_error.to_string().contains("tuple")
                || common_error.to_string().contains("wire profile"),
            "unexpected refusal: {common_error}"
        );

        let mut manifest_drift = fixture.authorization;
        manifest_drift["payload"]["targets"]["macos_aarch64"]["family_tuple"]["manifest_identity"] =
            json!(digest_text(b"synthetic-wrong-manifest"));
        manifest_drift["payload"]["targets"]["macos_aarch64"]["manifest_identity"] =
            json!(digest_text(b"synthetic-wrong-manifest"));
        let mut discovery_receipts = fixture.discovery_receipts;
        let mut mac_receipt: Value =
            serde_json::from_slice(&discovery_receipts[0]).expect("discovery receipt JSON");
        mac_receipt["family_tuple"]["manifest_identity"] =
            json!(digest_text(b"synthetic-wrong-manifest"));
        mac_receipt["manifest_identity"] = json!(digest_text(b"synthetic-wrong-manifest"));
        discovery_receipts[0] = json_bytes(&mac_receipt);
        manifest_drift["payload"]["targets"]["macos_aarch64"]["discovery_build_receipt_sha256"] =
            json!(hex(&sha256(&discovery_receipts[0])));
        reseal_private_payload(&mut manifest_drift);
        let manifest_drift = json_bytes(&manifest_drift);
        assert!(
            generate_private_transaction(
                &manifest_drift,
                sha256(&manifest_drift),
                &fixture.contract,
                &discovery_receipts,
            )
            .expect_err("manifest drift")
            .to_string()
            .contains("compiler reconstruction")
        );
    }

    #[test]
    fn exact_production_build_receipt_set_and_tuple_are_authenticated() {
        let (family, runner, plan, analyzer, evidence, receipts) = valid_build_receipt_parts();
        validate_family_authority(
            &family,
            &serde_json::from_value(qualification_value()).unwrap(),
            AuthorityMode::Production,
        )
        .expect("valid production family authority");
        let tuples =
            validate_build_receipts(&family, &runner, &plan, &analyzer, &evidence, &receipts)
                .expect("valid build receipt set");
        assert_eq!(tuples.len(), 2);

        assert!(
            validate_build_receipts(
                &family,
                &runner,
                &plan,
                &analyzer,
                &evidence,
                &receipts[..1],
            )
            .expect_err("partial receipt set")
            .to_string()
            .contains("partial")
        );

        let mut corrupted = receipts.clone();
        corrupted[1].push(b' ');
        assert!(
            validate_build_receipts(&family, &runner, &plan, &analyzer, &evidence, &corrupted,)
                .expect_err("receipt byte mutation")
                .to_string()
                .contains("differ from reviewed authorization")
        );
    }

    #[test]
    fn receipt_hash_cannot_authorize_a_different_family_tuple() {
        let (family, runner, plan, analyzer, evidence, mut receipts) = valid_build_receipt_parts();
        let mut changed: Value = serde_json::from_slice(&receipts[1]).expect("receipt JSON");
        changed["family_tuple"]["minimum_literal_bytes"] = json!(7);
        receipts[1] = json_bytes(&changed);

        let mut family_json = serde_json::to_value(&family).expect("family JSON");
        family_json["targets"][1]["build_receipt_sha256"] = json!(hex(&sha256(&receipts[1])));
        let family: AuthorizedFamily =
            serde_json::from_value(family_json).expect("changed synthetic family");
        let error =
            validate_build_receipts(&family, &runner, &plan, &analyzer, &evidence, &receipts)
                .expect_err("receipt tuple differs from reviewed tuple");
        assert!(
            error
                .to_string()
                .contains("differs from its reviewed tuple")
        );
    }
}
