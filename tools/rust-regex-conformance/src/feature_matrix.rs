//! Authenticated Cargo-feature matrix for the pinned upstream `regex` crate.

use std::{
    collections::{BTreeMap, BTreeSet},
    fs,
    io::Write,
    path::Path,
    process::Command,
};

use fre::{PortableBuilder, RustProfile, SearchLimits};
use fre_syntax::{CompatibilityProfile, ErrorCategory, ParseRequest, RustUnicodeFeatures, parse};
use serde::{Deserialize, Serialize};

use crate::{
    CandidateIdentity, InventoryError, UPSTREAM_REPOSITORY, UPSTREAM_REVISION, UPSTREAM_VERSION,
    authenticate_candidate_source, sha256,
};

/// Stable schema for an executed feature-matrix report.
pub const FEATURE_MATRIX_REPORT_SCHEMA: &str = "fre.upstream-rust-regex.feature-matrix-report.v1";
/// Exact number of public feature declarations in `regex` 1.12.4.
pub const FEATURE_MATRIX_DECLARED_FEATURES: usize = 22;
/// Exact number of mandatory matrix configurations.
pub const FEATURE_MATRIX_CONFIGURATIONS: usize = 25;

const UPSTREAM_PACKAGE: &str = "regex";
const UPSTREAM_PACKAGE_SHA256: &str =
    "f1292b7759ae1cb9ec195452d1390a074f0cd8541ab7a5a8c31cd6db45d4a6ba";
const VCS_INFO_SHA256: &str = "985255199f0cbe66b15087ac718981b349db800d87b913da314e95d065ceb2f5";
const MANIFEST_ORIG_SHA256: &str =
    "2fd5c1a0957af57186560cfb501eceaa7761bc612b26245be792284eee4763e0";
const MANIFEST_NORMALIZED_SHA256: &str =
    "746039e74f5192917d239506562018bcd8c31851b18caf042d7726e5502f090b";
const LOCK_SHA256: &str = "dd467e20d7e21dcf5c5305b0c58a8b05de56fca11719d371e5f278cb1fc7c182";
const MAX_AUTHENTICATED_FILE_BYTES: u64 = 4 * 1_048_576;

const AUTHENTICATED_SOURCES: &[(&str, &str)] = &[
    (
        "src/builders.rs",
        "d08f5867d8b994395546e318860d05e00cd70347223505b43d578b8d1477fe8f",
    ),
    (
        "src/bytes.rs",
        "cce2b7012f5896cf82fc3086bf8128dc9efe2b69bf6917d041c1a171eabacdc0",
    ),
    (
        "src/error.rs",
        "362c126a701852b355906acdb2c19ee31230570a408bbe52deb2803a1dc77039",
    ),
    (
        "src/find_byte.rs",
        "e17cd3b765467685946707840b92ea4e37d3c11081fbf316174a15858cd4bd99",
    ),
    (
        "src/lib.rs",
        "033460754d7a51fb9fa90ad096f76dbaaf10dc4c49f1195bb088fe23d35ded75",
    ),
    (
        "src/pattern.rs",
        "53971d02dde4f8e69055c36e7c56c6c872f0302161bf0977a02b97dc8a152d46",
    ),
    (
        "tests/lib.rs",
        "9bffc95568c09ac95b6a3e7ca64b6e858a0552d0c0b0fca2c447da3b9c0a45a2",
    ),
];

const PACKAGE_INTEGRATION_MISSING: &[&str] = &[
    "tests/fuzz/mod.rs",
    "testdata/fowler/basic.toml",
    "testdata/fowler/nullsubexpr.toml",
    "testdata/fowler/repetition.toml",
];

const EXPECTED_FEATURES: &[(&str, &[&str])] = &[
    (
        "default",
        &["std", "perf", "unicode", "regex-syntax/default"],
    ),
    (
        "logging",
        &[
            "aho-corasick?/logging",
            "memchr?/logging",
            "regex-automata/logging",
        ],
    ),
    ("pattern", &[]),
    (
        "perf",
        &[
            "perf-cache",
            "perf-dfa",
            "perf-onepass",
            "perf-backtrack",
            "perf-inline",
            "perf-literal",
        ],
    ),
    ("perf-backtrack", &["regex-automata/nfa-backtrack"]),
    ("perf-cache", &[]),
    ("perf-dfa", &["regex-automata/hybrid"]),
    (
        "perf-dfa-full",
        &["regex-automata/dfa-build", "regex-automata/dfa-search"],
    ),
    ("perf-inline", &["regex-automata/perf-inline"]),
    (
        "perf-literal",
        &[
            "dep:aho-corasick",
            "dep:memchr",
            "regex-automata/perf-literal",
        ],
    ),
    ("perf-onepass", &["regex-automata/dfa-onepass"]),
    (
        "std",
        &[
            "aho-corasick?/std",
            "memchr?/std",
            "regex-automata/std",
            "regex-syntax/std",
        ],
    ),
    (
        "unicode",
        &[
            "unicode-age",
            "unicode-bool",
            "unicode-case",
            "unicode-gencat",
            "unicode-perl",
            "unicode-script",
            "unicode-segment",
            "regex-automata/unicode",
            "regex-syntax/unicode",
        ],
    ),
    (
        "unicode-age",
        &["regex-automata/unicode-age", "regex-syntax/unicode-age"],
    ),
    (
        "unicode-bool",
        &["regex-automata/unicode-bool", "regex-syntax/unicode-bool"],
    ),
    (
        "unicode-case",
        &["regex-automata/unicode-case", "regex-syntax/unicode-case"],
    ),
    (
        "unicode-gencat",
        &[
            "regex-automata/unicode-gencat",
            "regex-syntax/unicode-gencat",
        ],
    ),
    (
        "unicode-perl",
        &[
            "regex-automata/unicode-perl",
            "regex-automata/unicode-word-boundary",
            "regex-syntax/unicode-perl",
        ],
    ),
    (
        "unicode-script",
        &[
            "regex-automata/unicode-script",
            "regex-syntax/unicode-script",
        ],
    ),
    (
        "unicode-segment",
        &[
            "regex-automata/unicode-segment",
            "regex-syntax/unicode-segment",
        ],
    ),
    ("unstable", &["pattern"]),
    ("use_std", &["std"]),
];

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum SemanticContract {
    HighLevelUnicode,
    RebarUnicode,
    NoUnicode,
    AgeUnicode,
    MissingUnicodeAvailabilityProfile,
    NightlyPatternApi,
}

#[derive(Clone, Copy, Debug)]
struct ConfigurationSpec {
    id: &'static str,
    default_features: bool,
    features: &'static [&'static str],
    semantic: SemanticContract,
}

struct QualifiedSemanticEvidence {
    high_level: String,
    rebar: String,
    no_unicode: String,
    age_unicode: String,
}

const CONFIGURATIONS: &[ConfigurationSpec] = &[
    ConfigurationSpec {
        id: "default",
        default_features: true,
        features: &[],
        semantic: SemanticContract::HighLevelUnicode,
    },
    ConfigurationSpec {
        id: "no-default",
        default_features: false,
        features: &[],
        semantic: SemanticContract::NoUnicode,
    },
    ConfigurationSpec {
        id: "std-only",
        default_features: false,
        features: &["std"],
        semantic: SemanticContract::NoUnicode,
    },
    ConfigurationSpec {
        id: "std-perf",
        default_features: false,
        features: &["std", "perf"],
        semantic: SemanticContract::NoUnicode,
    },
    ConfigurationSpec {
        id: "std-unicode",
        default_features: false,
        features: &["std", "unicode"],
        semantic: SemanticContract::HighLevelUnicode,
    },
    ConfigurationSpec {
        id: "std-perf-unicode",
        default_features: false,
        features: &["std", "perf", "unicode"],
        semantic: SemanticContract::HighLevelUnicode,
    },
    ConfigurationSpec {
        id: "rebar-default-logging-dfa-full",
        default_features: true,
        features: &["logging", "perf-dfa-full"],
        semantic: SemanticContract::RebarUnicode,
    },
    ConfigurationSpec {
        id: "use-std-unicode",
        default_features: false,
        features: &["use_std", "unicode"],
        semantic: SemanticContract::HighLevelUnicode,
    },
    ConfigurationSpec {
        id: "std-unicode-logging",
        default_features: false,
        features: &["std", "unicode", "logging"],
        semantic: SemanticContract::HighLevelUnicode,
    },
    ConfigurationSpec {
        id: "perf-backtrack",
        default_features: false,
        features: &["std", "unicode", "perf-backtrack"],
        semantic: SemanticContract::HighLevelUnicode,
    },
    ConfigurationSpec {
        id: "perf-cache",
        default_features: false,
        features: &["std", "unicode", "perf-cache"],
        semantic: SemanticContract::HighLevelUnicode,
    },
    ConfigurationSpec {
        id: "perf-dfa",
        default_features: false,
        features: &["std", "unicode", "perf-dfa"],
        semantic: SemanticContract::HighLevelUnicode,
    },
    ConfigurationSpec {
        id: "perf-dfa-full",
        default_features: false,
        features: &["std", "unicode", "perf-dfa-full"],
        semantic: SemanticContract::HighLevelUnicode,
    },
    ConfigurationSpec {
        id: "perf-inline",
        default_features: false,
        features: &["std", "unicode", "perf-inline"],
        semantic: SemanticContract::HighLevelUnicode,
    },
    ConfigurationSpec {
        id: "perf-literal",
        default_features: false,
        features: &["std", "unicode", "perf-literal"],
        semantic: SemanticContract::HighLevelUnicode,
    },
    ConfigurationSpec {
        id: "perf-onepass",
        default_features: false,
        features: &["std", "unicode", "perf-onepass"],
        semantic: SemanticContract::HighLevelUnicode,
    },
    ConfigurationSpec {
        id: "unicode-age",
        default_features: false,
        features: &["std", "unicode-age"],
        semantic: SemanticContract::AgeUnicode,
    },
    ConfigurationSpec {
        id: "unicode-bool",
        default_features: false,
        features: &["std", "unicode-bool"],
        semantic: SemanticContract::MissingUnicodeAvailabilityProfile,
    },
    ConfigurationSpec {
        id: "unicode-case",
        default_features: false,
        features: &["std", "unicode-case"],
        semantic: SemanticContract::MissingUnicodeAvailabilityProfile,
    },
    ConfigurationSpec {
        id: "unicode-gencat",
        default_features: false,
        features: &["std", "unicode-gencat"],
        semantic: SemanticContract::MissingUnicodeAvailabilityProfile,
    },
    ConfigurationSpec {
        id: "unicode-perl",
        default_features: false,
        features: &["std", "unicode-perl"],
        semantic: SemanticContract::MissingUnicodeAvailabilityProfile,
    },
    ConfigurationSpec {
        id: "unicode-script",
        default_features: false,
        features: &["std", "unicode-script"],
        semantic: SemanticContract::MissingUnicodeAvailabilityProfile,
    },
    ConfigurationSpec {
        id: "unicode-segment",
        default_features: false,
        features: &["std", "unicode-segment"],
        semantic: SemanticContract::MissingUnicodeAvailabilityProfile,
    },
    ConfigurationSpec {
        id: "pattern",
        default_features: false,
        features: &["std", "unicode", "pattern"],
        semantic: SemanticContract::NightlyPatternApi,
    },
    ConfigurationSpec {
        id: "unstable",
        default_features: false,
        features: &["std", "unicode", "unstable"],
        semantic: SemanticContract::NightlyPatternApi,
    },
];

/// Why a mandatory feature configuration cannot currently be claimed as pass.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum FeatureMatrixUnsupportedKind {
    FreProfileGranularity,
    Toolchain,
    FreApiSurface,
}

/// Mandatory result for one feature configuration. There is no skip state.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "kebab-case", tag = "status")]
pub enum FeatureMatrixDisposition {
    Pass {
        semantic_evidence_sha256: String,
    },
    Unsupported {
        kind: FeatureMatrixUnsupportedKind,
        cargo_check_passed: bool,
        reason_code: String,
    },
    Fault {
        stage: String,
        evidence_sha256: String,
        reason_code: String,
    },
}

/// Exact authenticated upstream file used by the matrix gate.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct FeatureMatrixSourceFile {
    pub path: String,
    pub sha256: String,
}

/// Exact upstream package and declared-feature identity.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct FeatureMatrixSourceIdentity {
    pub repository: String,
    pub package: String,
    pub version: String,
    pub revision: String,
    pub package_sha256: String,
    pub vcs_info_sha256: String,
    pub manifest_orig_sha256: String,
    pub manifest_normalized_sha256: String,
    pub lock_sha256: String,
    pub declared_features: BTreeMap<String, Vec<String>>,
    pub authenticated_sources: Vec<FeatureMatrixSourceFile>,
    pub packaged_integration_suite_outcome: String,
    pub packaged_integration_suite_missing: Vec<String>,
}

/// Stable compiler identity needed to distinguish unsupported nightly rows.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct FeatureMatrixToolchain {
    pub rustc_release: String,
    pub rustc_host: String,
    pub cargo_release: String,
    pub nightly: bool,
}

/// One mandatory feature configuration receipt.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct FeatureMatrixReceipt {
    pub configuration_id: String,
    pub default_features: bool,
    pub features: Vec<String>,
    pub cargo_operation: String,
    pub disposition: FeatureMatrixDisposition,
}

/// Complete result cardinalities for the fixed matrix denominator.
#[derive(Clone, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct FeatureMatrixCounts {
    pub pass: usize,
    pub unsupported_profile: usize,
    pub unsupported_toolchain: usize,
    pub unsupported_api: usize,
    pub fault: usize,
    pub total: usize,
}

/// Payload authenticated by [`FeatureMatrixReport::payload_sha256`].
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct FeatureMatrixReportPayload {
    pub source: FeatureMatrixSourceIdentity,
    pub candidate: CandidateIdentity,
    pub toolchain: FeatureMatrixToolchain,
    pub counts: FeatureMatrixCounts,
    pub receipts: Vec<FeatureMatrixReceipt>,
}

/// Immutable report for all fixed feature configurations.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct FeatureMatrixReport {
    pub schema: String,
    pub payload_sha256: String,
    pub payload: FeatureMatrixReportPayload,
}

/// Authenticate and execute every mandatory matrix row.
pub fn build_feature_matrix_report(
    upstream_package: &Path,
    candidate_path: &Path,
    target_dir: &Path,
) -> Result<FeatureMatrixReport, InventoryError> {
    validate_contract()?;
    let source = authenticate_upstream_package(upstream_package)?;
    let candidate = authenticate_candidate_source(candidate_path)?;
    let toolchain = authenticate_toolchain()?;
    validate_target_dir(target_dir)?;
    let evidence = QualifiedSemanticEvidence {
        high_level: run_semantic_contract(RustProfile::regex_1_12_4())?,
        rebar: run_semantic_contract(RustProfile::rebar_1_12_4())?,
        no_unicode: run_no_unicode_contract()?,
        age_unicode: run_age_unicode_contract()?,
    };
    let mut receipts = Vec::with_capacity(CONFIGURATIONS.len());
    for spec in CONFIGURATIONS {
        receipts.push(run_configuration(
            spec,
            upstream_package,
            target_dir,
            &toolchain,
            &evidence,
        ));
    }
    let counts = FeatureMatrixCounts::from_receipts(&receipts)?;
    let payload = FeatureMatrixReportPayload {
        source,
        candidate,
        toolchain,
        counts,
        receipts,
    };
    let payload_sha256 =
        sha256(&serde_json::to_vec(&payload).map_err(|error| {
            InventoryError::new(format!("encode feature matrix payload: {error}"))
        })?);
    let report = FeatureMatrixReport {
        schema: FEATURE_MATRIX_REPORT_SCHEMA.to_owned(),
        payload_sha256,
        payload,
    };
    report.validate()?;
    Ok(report)
}

/// Read and authenticate a complete feature-matrix report.
pub fn read_feature_matrix_report(path: &Path) -> Result<FeatureMatrixReport, InventoryError> {
    let bytes = fs::read(path).map_err(|error| {
        InventoryError::new(format!(
            "read feature matrix report {}: {error}",
            path.display()
        ))
    })?;
    let report: FeatureMatrixReport = serde_json::from_slice(&bytes).map_err(|error| {
        InventoryError::new(format!(
            "decode feature matrix report {}: {error}",
            path.display()
        ))
    })?;
    report.validate()?;
    Ok(report)
}

/// Atomically write canonical pretty JSON without overwriting an existing file.
pub fn write_feature_matrix_report(
    path: &Path,
    report: &FeatureMatrixReport,
) -> Result<(), InventoryError> {
    report.validate()?;
    if path.exists() || fs::symlink_metadata(path).is_ok() {
        return Err(InventoryError::new(format!(
            "feature matrix output already exists: {}",
            path.display()
        )));
    }
    let parent = path.parent().ok_or_else(|| {
        InventoryError::new(format!(
            "feature matrix output has no parent: {}",
            path.display()
        ))
    })?;
    let metadata = fs::symlink_metadata(parent).map_err(|error| {
        InventoryError::new(format!("stat output parent {}: {error}", parent.display()))
    })?;
    if metadata.file_type().is_symlink() || !metadata.file_type().is_dir() {
        return Err(InventoryError::new(
            "feature matrix output parent must be a real directory",
        ));
    }
    let name = path
        .file_name()
        .and_then(|name| name.to_str())
        .ok_or_else(|| {
            InventoryError::new(format!("invalid feature matrix output: {}", path.display()))
        })?;
    let temporary = parent.join(format!(".{name}.tmp.{}", std::process::id()));
    let mut output = fs::OpenOptions::new()
        .create_new(true)
        .write(true)
        .open(&temporary)
        .map_err(|error| InventoryError::new(format!("create {}: {error}", temporary.display())))?;
    let bytes = serde_json::to_vec_pretty(report)
        .map_err(|error| InventoryError::new(format!("encode feature matrix report: {error}")))?;
    let result = (|| {
        output.write_all(&bytes).map_err(|error| {
            InventoryError::new(format!("write {}: {error}", temporary.display()))
        })?;
        output.write_all(b"\n").map_err(|error| {
            InventoryError::new(format!("write newline {}: {error}", temporary.display()))
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

impl FeatureMatrixReport {
    /// Validate source identity, fixed denominator, ordering, and disposition counts.
    pub fn validate(&self) -> Result<(), InventoryError> {
        validate_contract()?;
        if self.schema != FEATURE_MATRIX_REPORT_SCHEMA {
            return Err(InventoryError::new("feature matrix schema mismatch"));
        }
        let expected_hash = sha256(&serde_json::to_vec(&self.payload).map_err(|error| {
            InventoryError::new(format!("encode feature matrix payload: {error}"))
        })?);
        if self.payload_sha256 != expected_hash {
            return Err(InventoryError::new(
                "feature matrix payload SHA-256 mismatch",
            ));
        }
        validate_source_identity(&self.payload.source)?;
        validate_candidate(&self.payload.candidate)?;
        validate_toolchain(&self.payload.toolchain)?;
        if self.payload.receipts.len() != CONFIGURATIONS.len() {
            return Err(InventoryError::new(
                "feature matrix receipt denominator mismatch",
            ));
        }
        for (receipt, spec) in self.payload.receipts.iter().zip(CONFIGURATIONS) {
            if receipt.configuration_id != spec.id
                || receipt.default_features != spec.default_features
                || receipt.features
                    != spec
                        .features
                        .iter()
                        .map(|feature| (*feature).to_owned())
                        .collect::<Vec<_>>()
                || receipt.cargo_operation != "offline-locked-check-lib"
            {
                return Err(InventoryError::new(format!(
                    "feature matrix receipt contract mismatch for {}",
                    spec.id
                )));
            }
            validate_disposition(spec, &self.payload.toolchain, &receipt.disposition)?;
        }
        let counts = FeatureMatrixCounts::from_receipts(&self.payload.receipts)?;
        if counts != self.payload.counts {
            return Err(InventoryError::new("feature matrix count mismatch"));
        }
        Ok(())
    }
}

impl FeatureMatrixCounts {
    fn from_receipts(receipts: &[FeatureMatrixReceipt]) -> Result<Self, InventoryError> {
        let mut counts = Self::default();
        for receipt in receipts {
            match &receipt.disposition {
                FeatureMatrixDisposition::Pass { .. } => {
                    checked_increment(&mut counts.pass, "pass")?;
                }
                FeatureMatrixDisposition::Unsupported { kind, .. } => match kind {
                    FeatureMatrixUnsupportedKind::FreProfileGranularity => {
                        checked_increment(&mut counts.unsupported_profile, "unsupported profile")?;
                    }
                    FeatureMatrixUnsupportedKind::Toolchain => {
                        checked_increment(
                            &mut counts.unsupported_toolchain,
                            "unsupported toolchain",
                        )?;
                    }
                    FeatureMatrixUnsupportedKind::FreApiSurface => {
                        checked_increment(&mut counts.unsupported_api, "unsupported API")?;
                    }
                },
                FeatureMatrixDisposition::Fault { .. } => {
                    checked_increment(&mut counts.fault, "fault")?;
                }
            }
            counts.total = counts
                .total
                .checked_add(1)
                .ok_or_else(|| InventoryError::new("feature matrix total overflow"))?;
        }
        Ok(counts)
    }
}

fn checked_increment(value: &mut usize, label: &str) -> Result<(), InventoryError> {
    *value = value
        .checked_add(1)
        .ok_or_else(|| InventoryError::new(format!("feature matrix {label} count overflow")))?;
    Ok(())
}

fn run_configuration(
    spec: &ConfigurationSpec,
    upstream: &Path,
    target_root: &Path,
    toolchain: &FeatureMatrixToolchain,
    evidence: &QualifiedSemanticEvidence,
) -> FeatureMatrixReceipt {
    let disposition = if spec.semantic == SemanticContract::NightlyPatternApi && !toolchain.nightly
    {
        FeatureMatrixDisposition::Unsupported {
            kind: FeatureMatrixUnsupportedKind::Toolchain,
            cargo_check_passed: false,
            reason_code: "toolchain.nightly-pattern-required".to_owned(),
        }
    } else {
        match cargo_check_configuration(spec, upstream, target_root) {
            Ok(()) => match spec.semantic {
                SemanticContract::HighLevelUnicode => FeatureMatrixDisposition::Pass {
                    semantic_evidence_sha256: evidence.high_level.clone(),
                },
                SemanticContract::RebarUnicode => FeatureMatrixDisposition::Pass {
                    semantic_evidence_sha256: evidence.rebar.clone(),
                },
                SemanticContract::NoUnicode => FeatureMatrixDisposition::Pass {
                    semantic_evidence_sha256: evidence.no_unicode.clone(),
                },
                SemanticContract::AgeUnicode => FeatureMatrixDisposition::Pass {
                    semantic_evidence_sha256: evidence.age_unicode.clone(),
                },
                SemanticContract::MissingUnicodeAvailabilityProfile => {
                    FeatureMatrixDisposition::Unsupported {
                        kind: FeatureMatrixUnsupportedKind::FreProfileGranularity,
                        cargo_check_passed: true,
                        reason_code: "fre-profile.unicode-feature-availability-unrepresented"
                            .to_owned(),
                    }
                }
                SemanticContract::NightlyPatternApi => FeatureMatrixDisposition::Unsupported {
                    kind: FeatureMatrixUnsupportedKind::FreApiSurface,
                    cargo_check_passed: true,
                    reason_code: "fre-api.pattern-trait-unimplemented".to_owned(),
                },
            },
            Err((reason_code, evidence_sha256)) => FeatureMatrixDisposition::Fault {
                stage: "cargo-check-lib".to_owned(),
                evidence_sha256,
                reason_code,
            },
        }
    };
    FeatureMatrixReceipt {
        configuration_id: spec.id.to_owned(),
        default_features: spec.default_features,
        features: spec
            .features
            .iter()
            .map(|feature| (*feature).to_owned())
            .collect(),
        cargo_operation: "offline-locked-check-lib".to_owned(),
        disposition,
    }
}

fn cargo_check_configuration(
    spec: &ConfigurationSpec,
    upstream: &Path,
    target_root: &Path,
) -> Result<(), (String, String)> {
    let target = target_root.join(spec.id);
    if let Err(error) = ensure_target_subdir(&target) {
        return Err((
            "gate.target-create-failed".to_owned(),
            sha256(error.to_string().as_bytes()),
        ));
    }
    let mut command = Command::new("cargo");
    command
        .arg("check")
        .arg("--offline")
        .arg("--locked")
        .arg("--manifest-path")
        .arg(upstream.join("Cargo.toml"))
        .arg("--lib")
        .env("CARGO_NET_OFFLINE", "true")
        .env("CARGO_TARGET_DIR", target);
    if !spec.default_features {
        command.arg("--no-default-features");
    }
    if !spec.features.is_empty() {
        command.arg("--features").arg(spec.features.join(","));
    }
    let output = match command.output() {
        Ok(output) => output,
        Err(error) => {
            return Err((
                "gate.cargo-exec-failed".to_owned(),
                sha256(error.to_string().as_bytes()),
            ));
        }
    };
    if output.status.success() {
        Ok(())
    } else {
        let mut evidence = output.stdout;
        evidence.extend_from_slice(&output.stderr);
        Err(("upstream.cargo-check-failed".to_owned(), sha256(&evidence)))
    }
}

fn ensure_target_subdir(path: &Path) -> Result<(), InventoryError> {
    match fs::create_dir(path) {
        Ok(()) => Ok(()),
        Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {
            let metadata = fs::symlink_metadata(path).map_err(|stat_error| {
                InventoryError::new(format!(
                    "stat feature target {}: {stat_error}",
                    path.display()
                ))
            })?;
            if metadata.file_type().is_symlink() || !metadata.file_type().is_dir() {
                return Err(InventoryError::new(format!(
                    "feature target is not a real directory: {}",
                    path.display()
                )));
            }
            Ok(())
        }
        Err(error) => Err(InventoryError::new(format!(
            "create feature target {}: {error}",
            path.display()
        ))),
    }
}

fn run_semantic_contract(profile: RustProfile) -> Result<String, InventoryError> {
    let is_rebar = matches!(
        profile.constructor,
        fre_syntax::RustConstructor::RebarMeta { .. }
    );
    let compatibility = CompatibilityProfile::RustBytes(profile.clone());
    let parsed = parse(ParseRequest::rust(r"\p{Greek}+", compatibility)).map_err(|error| {
        InventoryError::new(format!(
            "feature matrix Unicode semantic parse failed: {error}"
        ))
    })?;
    if parsed.summary.class_ranges == 0 {
        return Err(InventoryError::new(
            "feature matrix Unicode semantic parse produced no class ranges",
        ));
    }
    let regex = PortableBuilder::new("needle")
        .profile(profile)
        .build()
        .map_err(|error| {
            InventoryError::new(format!("feature matrix literal build failed: {error}"))
        })?;
    let (found, _) = regex
        .find(b"xxneedleyy", SearchLimits::default())
        .map_err(|error| {
            InventoryError::new(format!("feature matrix literal search failed: {error}"))
        })?;
    let found = found.ok_or_else(|| {
        InventoryError::new("feature matrix literal semantic check found no match")
    })?;
    if found.start() != 2 || found.end() != 8 {
        return Err(InventoryError::new(
            "feature matrix literal semantic check returned wrong span",
        ));
    }
    let evidence = if is_rebar {
        b"regex-1.12.4-rebar-unicode;greek-class=parsed;literal-span=2..8".as_slice()
    } else {
        b"regex-1.12.4-high-level-unicode;greek-class=parsed;literal-span=2..8".as_slice()
    };
    Ok(sha256(evidence))
}

const NO_UNICODE_WITNESSES: &[(&str, &str)] = &[
    ("age", r"\p{Age:6.0}"),
    ("bool", r"\p{Alphabetic}"),
    ("case", r"(?i:\u{03B4})"),
    ("gencat", r"\pL"),
    ("perl", r"\b\w\b"),
    ("script", r"\p{Greek}"),
    ("segment", r"\p{Grapheme_Cluster_Break=Extend}"),
];

fn run_no_unicode_contract() -> Result<String, InventoryError> {
    let mut profile = RustProfile::regex_1_12_4();
    profile.unicode_features = RustUnicodeFeatures::NONE;
    parse(ParseRequest::rust(
        "ascii",
        CompatibilityProfile::RustText(profile.clone()),
    ))
    .map_err(|error| {
        InventoryError::new(format!(
            "no-Unicode profile rejected table-free syntax: {error}"
        ))
    })?;

    for &(family, pattern) in NO_UNICODE_WITNESSES {
        let error = parse(ParseRequest::rust(
            pattern,
            CompatibilityProfile::RustText(profile.clone()),
        ))
        .expect_err("every Unicode data-family witness must be refused");
        if error.category != ErrorCategory::UpstreamRustSyntax
            || !error.message.contains("unavailable in this Rust profile")
        {
            return Err(InventoryError::new(format!(
                "no-Unicode {family} witness returned an unauthenticated refusal: {error}"
            )));
        }
    }
    Ok(expected_no_unicode_evidence())
}

fn expected_no_unicode_evidence() -> String {
    let mut evidence = "regex-1.12.4-no-unicode;ascii=parsed".to_owned();
    for &(family, _) in NO_UNICODE_WITNESSES {
        evidence.push(';');
        evidence.push_str(family);
        evidence.push_str("=refused");
    }
    sha256(evidence.as_bytes())
}

fn run_age_unicode_contract() -> Result<String, InventoryError> {
    let mut profile = RustProfile::regex_1_12_4();
    profile.unicode_features = RustUnicodeFeatures::AGE;
    parse(ParseRequest::rust(
        "ascii",
        CompatibilityProfile::RustText(profile.clone()),
    ))
    .map_err(|error| {
        InventoryError::new(format!(
            "unicode-age profile rejected table-free syntax: {error}"
        ))
    })?;
    let age = parse(ParseRequest::rust(
        r"\p{Age:6.0}",
        CompatibilityProfile::RustText(profile.clone()),
    ))
    .map_err(|error| {
        InventoryError::new(format!(
            "unicode-age profile rejected its Age witness: {error}"
        ))
    })?;
    if age.summary.class_ranges == 0 {
        return Err(InventoryError::new(
            "unicode-age witness produced no class ranges",
        ));
    }
    for &(family, pattern) in &NO_UNICODE_WITNESSES[1..] {
        let result = parse(ParseRequest::rust(
            pattern,
            CompatibilityProfile::RustText(profile.clone()),
        ));
        let Err(error) = result else {
            return Err(InventoryError::new(format!(
                "unicode-age profile falsely admitted {family} witness {pattern}"
            )));
        };
        if error.category != ErrorCategory::UpstreamRustSyntax
            || !error.message.contains("unavailable in this Rust profile")
        {
            return Err(InventoryError::new(format!(
                "unicode-age {family} witness returned an unauthenticated refusal: {error}"
            )));
        }
    }
    Ok(expected_age_unicode_evidence())
}

fn expected_age_unicode_evidence() -> String {
    let mut evidence = "regex-1.12.4-unicode-age;ascii=parsed;age=parsed".to_owned();
    for &(family, _) in &NO_UNICODE_WITNESSES[1..] {
        evidence.push(';');
        evidence.push_str(family);
        evidence.push_str("=refused");
    }
    sha256(evidence.as_bytes())
}

fn authenticate_upstream_package(
    root: &Path,
) -> Result<FeatureMatrixSourceIdentity, InventoryError> {
    let metadata = fs::symlink_metadata(root).map_err(|error| {
        InventoryError::new(format!("stat upstream package {}: {error}", root.display()))
    })?;
    if metadata.file_type().is_symlink() || !metadata.file_type().is_dir() {
        return Err(InventoryError::new(
            "upstream package must be a real directory",
        ));
    }
    authenticate_file(root, ".cargo_vcs_info.json", VCS_INFO_SHA256)?;
    authenticate_file(root, "Cargo.toml.orig", MANIFEST_ORIG_SHA256)?;
    authenticate_file(root, "Cargo.toml", MANIFEST_NORMALIZED_SHA256)?;
    authenticate_file(root, "Cargo.lock", LOCK_SHA256)?;
    let vcs_bytes = fs::read(root.join(".cargo_vcs_info.json"))
        .map_err(|error| InventoryError::new(format!("read upstream VCS identity: {error}")))?;
    let vcs: serde_json::Value = serde_json::from_slice(&vcs_bytes)
        .map_err(|error| InventoryError::new(format!("decode upstream VCS identity: {error}")))?;
    if vcs.pointer("/git/sha1").and_then(serde_json::Value::as_str) != Some(UPSTREAM_REVISION) {
        return Err(InventoryError::new("upstream VCS revision mismatch"));
    }
    let manifest_bytes = fs::read(root.join("Cargo.toml.orig"))
        .map_err(|error| InventoryError::new(format!("read upstream manifest: {error}")))?;
    let declared_features = parse_declared_features(&manifest_bytes)?;
    if declared_features != expected_features() {
        return Err(InventoryError::new(
            "upstream declared feature inventory mismatch",
        ));
    }
    let mut authenticated_sources = Vec::with_capacity(AUTHENTICATED_SOURCES.len());
    for &(path, expected) in AUTHENTICATED_SOURCES {
        authenticate_file(root, path, expected)?;
        authenticated_sources.push(FeatureMatrixSourceFile {
            path: path.to_owned(),
            sha256: expected.to_owned(),
        });
    }
    for missing in PACKAGE_INTEGRATION_MISSING {
        let path = root.join(missing);
        if path.exists() || fs::symlink_metadata(&path).is_ok() {
            return Err(InventoryError::new(format!(
                "packaged integration limitation changed at {missing}"
            )));
        }
    }
    Ok(FeatureMatrixSourceIdentity {
        repository: UPSTREAM_REPOSITORY.to_owned(),
        package: UPSTREAM_PACKAGE.to_owned(),
        version: UPSTREAM_VERSION.to_owned(),
        revision: UPSTREAM_REVISION.to_owned(),
        package_sha256: UPSTREAM_PACKAGE_SHA256.to_owned(),
        vcs_info_sha256: VCS_INFO_SHA256.to_owned(),
        manifest_orig_sha256: MANIFEST_ORIG_SHA256.to_owned(),
        manifest_normalized_sha256: MANIFEST_NORMALIZED_SHA256.to_owned(),
        lock_sha256: LOCK_SHA256.to_owned(),
        declared_features,
        authenticated_sources,
        packaged_integration_suite_outcome: "unsupported-source-package-incomplete".to_owned(),
        packaged_integration_suite_missing: PACKAGE_INTEGRATION_MISSING
            .iter()
            .map(|path| (*path).to_owned())
            .collect(),
    })
}

fn authenticate_file(root: &Path, relative: &str, expected: &str) -> Result<(), InventoryError> {
    let path = root.join(relative);
    let metadata = fs::symlink_metadata(&path)
        .map_err(|error| InventoryError::new(format!("stat {}: {error}", path.display())))?;
    if metadata.file_type().is_symlink()
        || !metadata.file_type().is_file()
        || metadata.len() > MAX_AUTHENTICATED_FILE_BYTES
    {
        return Err(InventoryError::new(format!(
            "invalid authenticated upstream file {relative}"
        )));
    }
    let bytes = fs::read(&path)
        .map_err(|error| InventoryError::new(format!("read {}: {error}", path.display())))?;
    if sha256(&bytes) != expected {
        return Err(InventoryError::new(format!(
            "authenticated upstream file hash mismatch for {relative}"
        )));
    }
    Ok(())
}

fn parse_declared_features(bytes: &[u8]) -> Result<BTreeMap<String, Vec<String>>, InventoryError> {
    let source = std::str::from_utf8(bytes)
        .map_err(|error| InventoryError::new(format!("upstream manifest is not UTF-8: {error}")))?;
    let manifest: toml::Value = toml::from_str(source)
        .map_err(|error| InventoryError::new(format!("decode upstream manifest: {error}")))?;
    let table = manifest
        .get("features")
        .and_then(toml::Value::as_table)
        .ok_or_else(|| InventoryError::new("upstream manifest has no feature table"))?;
    let mut features = BTreeMap::new();
    for (name, values) in table {
        let values = values.as_array().ok_or_else(|| {
            InventoryError::new(format!("upstream feature {name} is not an array"))
        })?;
        let mut enables = Vec::with_capacity(values.len());
        for value in values {
            let value = value.as_str().ok_or_else(|| {
                InventoryError::new(format!("upstream feature {name} has a non-string member"))
            })?;
            enables.push(value.to_owned());
        }
        if features.insert(name.clone(), enables).is_some() {
            return Err(InventoryError::new(format!(
                "duplicate upstream feature {name}"
            )));
        }
    }
    Ok(features)
}

fn expected_features() -> BTreeMap<String, Vec<String>> {
    EXPECTED_FEATURES
        .iter()
        .map(|&(name, values)| {
            (
                name.to_owned(),
                values.iter().map(|value| (*value).to_owned()).collect(),
            )
        })
        .collect()
}

fn validate_contract() -> Result<(), InventoryError> {
    if EXPECTED_FEATURES.len() != FEATURE_MATRIX_DECLARED_FEATURES
        || CONFIGURATIONS.len() != FEATURE_MATRIX_CONFIGURATIONS
    {
        return Err(InventoryError::new(
            "compiled feature matrix cardinality mismatch",
        ));
    }
    let declared = expected_features();
    let mut ids = BTreeSet::new();
    let mut covered = BTreeSet::new();
    covered.insert("default".to_owned());
    for spec in CONFIGURATIONS {
        if spec.id.is_empty() || !ids.insert(spec.id) {
            return Err(InventoryError::new(
                "invalid or duplicate feature matrix configuration ID",
            ));
        }
        let mut row_features = BTreeSet::new();
        for feature in spec.features {
            if !declared.contains_key(*feature) || !row_features.insert(*feature) {
                return Err(InventoryError::new(format!(
                    "unknown or duplicate matrix feature {feature}"
                )));
            }
            covered.insert((*feature).to_owned());
        }
    }
    if covered != declared.keys().cloned().collect() {
        return Err(InventoryError::new(
            "feature matrix does not cover every declared feature",
        ));
    }
    Ok(())
}

fn authenticate_toolchain() -> Result<FeatureMatrixToolchain, InventoryError> {
    let rustc = command_utf8("rustc", &["--version", "--verbose"])?;
    let cargo = command_utf8("cargo", &["--version"])?;
    let rustc_release = labeled_line(&rustc, "release")?;
    let rustc_host = labeled_line(&rustc, "host")?;
    let cargo_release = cargo
        .strip_prefix("cargo ")
        .and_then(|value| value.split_whitespace().next())
        .ok_or_else(|| InventoryError::new("unrecognized cargo version output"))?
        .to_owned();
    let nightly = rustc_release.contains("nightly") || rustc_release.contains("dev");
    let toolchain = FeatureMatrixToolchain {
        rustc_release,
        rustc_host,
        cargo_release,
        nightly,
    };
    validate_toolchain(&toolchain)?;
    Ok(toolchain)
}

fn command_utf8(program: &str, args: &[&str]) -> Result<String, InventoryError> {
    let output = Command::new(program)
        .args(args)
        .output()
        .map_err(|error| InventoryError::new(format!("run {program} {args:?}: {error}")))?;
    if !output.status.success() {
        return Err(InventoryError::new(format!(
            "{program} {args:?} failed with {}",
            output.status
        )));
    }
    String::from_utf8(output.stdout)
        .map(|value| value.trim().to_owned())
        .map_err(|error| InventoryError::new(format!("{program} output is not UTF-8: {error}")))
}

fn labeled_line(output: &str, label: &str) -> Result<String, InventoryError> {
    let prefix = format!("{label}: ");
    output
        .lines()
        .find_map(|line| line.strip_prefix(&prefix))
        .filter(|value| !value.is_empty())
        .map(str::to_owned)
        .ok_or_else(|| InventoryError::new(format!("missing {label} in rustc identity")))
}

fn validate_target_dir(path: &Path) -> Result<(), InventoryError> {
    let metadata = fs::symlink_metadata(path).map_err(|error| {
        InventoryError::new(format!(
            "stat feature matrix target {}: {error}",
            path.display()
        ))
    })?;
    if metadata.file_type().is_symlink() || !metadata.file_type().is_dir() {
        return Err(InventoryError::new(
            "feature matrix target must be a real directory",
        ));
    }
    Ok(())
}

fn validate_source_identity(source: &FeatureMatrixSourceIdentity) -> Result<(), InventoryError> {
    if source.repository != UPSTREAM_REPOSITORY
        || source.package != UPSTREAM_PACKAGE
        || source.version != UPSTREAM_VERSION
        || source.revision != UPSTREAM_REVISION
        || source.package_sha256 != UPSTREAM_PACKAGE_SHA256
        || source.vcs_info_sha256 != VCS_INFO_SHA256
        || source.manifest_orig_sha256 != MANIFEST_ORIG_SHA256
        || source.manifest_normalized_sha256 != MANIFEST_NORMALIZED_SHA256
        || source.lock_sha256 != LOCK_SHA256
        || source.declared_features != expected_features()
        || source.packaged_integration_suite_outcome != "unsupported-source-package-incomplete"
        || source.packaged_integration_suite_missing
            != PACKAGE_INTEGRATION_MISSING
                .iter()
                .map(|path| (*path).to_owned())
                .collect::<Vec<_>>()
    {
        return Err(InventoryError::new(
            "feature matrix upstream identity mismatch",
        ));
    }
    let expected_sources = AUTHENTICATED_SOURCES
        .iter()
        .map(|&(path, hash)| FeatureMatrixSourceFile {
            path: path.to_owned(),
            sha256: hash.to_owned(),
        })
        .collect::<Vec<_>>();
    if source.authenticated_sources != expected_sources {
        return Err(InventoryError::new(
            "feature matrix authenticated source list mismatch",
        ));
    }
    Ok(())
}

fn validate_candidate(candidate: &CandidateIdentity) -> Result<(), InventoryError> {
    if candidate.revision.len() != 40
        || candidate.tree.len() != 40
        || !candidate
            .revision
            .bytes()
            .chain(candidate.tree.bytes())
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
        || !candidate.tracked_and_untracked_worktree_clean
    {
        return Err(InventoryError::new(
            "feature matrix candidate identity invalid",
        ));
    }
    Ok(())
}

fn validate_toolchain(toolchain: &FeatureMatrixToolchain) -> Result<(), InventoryError> {
    if toolchain.rustc_release.is_empty()
        || toolchain.rustc_host.is_empty()
        || toolchain.cargo_release.is_empty()
        || toolchain
            .rustc_release
            .bytes()
            .any(|byte| byte.is_ascii_control())
        || toolchain
            .rustc_host
            .bytes()
            .any(|byte| byte.is_ascii_control())
        || toolchain
            .cargo_release
            .bytes()
            .any(|byte| byte.is_ascii_control())
        || toolchain.nightly
            != (toolchain.rustc_release.contains("nightly")
                || toolchain.rustc_release.contains("dev"))
    {
        return Err(InventoryError::new(
            "feature matrix toolchain identity invalid",
        ));
    }
    Ok(())
}

fn validate_disposition(
    spec: &ConfigurationSpec,
    toolchain: &FeatureMatrixToolchain,
    disposition: &FeatureMatrixDisposition,
) -> Result<(), InventoryError> {
    match (spec.semantic, toolchain.nightly, disposition) {
        (
            SemanticContract::HighLevelUnicode | SemanticContract::RebarUnicode,
            _,
            FeatureMatrixDisposition::Pass {
                semantic_evidence_sha256,
            },
        ) if semantic_evidence_sha256 == &expected_semantic_evidence(spec.semantic) => Ok(()),
        (
            SemanticContract::NoUnicode,
            _,
            FeatureMatrixDisposition::Pass {
                semantic_evidence_sha256,
            },
        ) if semantic_evidence_sha256 == &expected_no_unicode_evidence() => Ok(()),
        (
            SemanticContract::AgeUnicode,
            _,
            FeatureMatrixDisposition::Pass {
                semantic_evidence_sha256,
            },
        ) if semantic_evidence_sha256 == &expected_age_unicode_evidence() => Ok(()),
        (
            SemanticContract::MissingUnicodeAvailabilityProfile,
            _,
            FeatureMatrixDisposition::Unsupported {
                kind: FeatureMatrixUnsupportedKind::FreProfileGranularity,
                cargo_check_passed: true,
                reason_code,
            },
        ) if reason_code == "fre-profile.unicode-feature-availability-unrepresented" => Ok(()),
        (
            SemanticContract::NightlyPatternApi,
            false,
            FeatureMatrixDisposition::Unsupported {
                kind: FeatureMatrixUnsupportedKind::Toolchain,
                cargo_check_passed: false,
                reason_code,
            },
        ) if reason_code == "toolchain.nightly-pattern-required" => Ok(()),
        (
            SemanticContract::NightlyPatternApi,
            true,
            FeatureMatrixDisposition::Unsupported {
                kind: FeatureMatrixUnsupportedKind::FreApiSurface,
                cargo_check_passed: true,
                reason_code,
            },
        ) if reason_code == "fre-api.pattern-trait-unimplemented" => Ok(()),
        (
            _,
            _,
            FeatureMatrixDisposition::Fault {
                stage,
                evidence_sha256,
                reason_code,
            },
        ) if stage == "cargo-check-lib"
            && is_sha256(evidence_sha256)
            && matches!(
                reason_code.as_str(),
                "gate.target-create-failed"
                    | "gate.cargo-exec-failed"
                    | "upstream.cargo-check-failed"
            ) =>
        {
            Ok(())
        }
        _ => Err(InventoryError::new(format!(
            "invalid feature matrix disposition for {}",
            spec.id
        ))),
    }
}

fn expected_semantic_evidence(contract: SemanticContract) -> String {
    let evidence = match contract {
        SemanticContract::HighLevelUnicode => {
            b"regex-1.12.4-high-level-unicode;greek-class=parsed;literal-span=2..8".as_slice()
        }
        SemanticContract::RebarUnicode => {
            b"regex-1.12.4-rebar-unicode;greek-class=parsed;literal-span=2..8".as_slice()
        }
        SemanticContract::NoUnicode => return expected_no_unicode_evidence(),
        SemanticContract::AgeUnicode => return expected_age_unicode_evidence(),
        SemanticContract::MissingUnicodeAvailabilityProfile
        | SemanticContract::NightlyPatternApi => b"unsupported".as_slice(),
    };
    sha256(evidence)
}

fn is_sha256(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn contract_covers_every_declared_feature_without_silent_rows() {
        validate_contract().expect("feature matrix contract validates");
        assert_eq!(expected_features().len(), FEATURE_MATRIX_DECLARED_FEATURES);
        assert_eq!(CONFIGURATIONS.len(), FEATURE_MATRIX_CONFIGURATIONS);
        assert_eq!(
            CONFIGURATIONS
                .iter()
                .filter(|spec| matches!(spec.semantic, SemanticContract::HighLevelUnicode))
                .count(),
            12
        );
        assert_eq!(
            CONFIGURATIONS
                .iter()
                .filter(|spec| matches!(spec.semantic, SemanticContract::RebarUnicode))
                .count(),
            1
        );
        assert_eq!(
            CONFIGURATIONS
                .iter()
                .filter(|spec| matches!(spec.semantic, SemanticContract::NoUnicode))
                .count(),
            3
        );
        assert_eq!(
            CONFIGURATIONS
                .iter()
                .filter(|spec| matches!(spec.semantic, SemanticContract::AgeUnicode))
                .count(),
            1
        );
        assert_eq!(
            CONFIGURATIONS
                .iter()
                .filter(|spec| matches!(
                    spec.semantic,
                    SemanticContract::MissingUnicodeAvailabilityProfile
                ))
                .count(),
            6
        );
        assert_eq!(
            CONFIGURATIONS
                .iter()
                .filter(|spec| matches!(spec.semantic, SemanticContract::NightlyPatternApi))
                .count(),
            2
        );
    }

    #[test]
    fn semantic_contracts_execute_real_fre_profiles() {
        let high_level =
            run_semantic_contract(RustProfile::regex_1_12_4()).expect("high-level semantic gate");
        let rebar =
            run_semantic_contract(RustProfile::rebar_1_12_4()).expect("Rebar semantic gate");
        assert!(is_sha256(&high_level));
        assert!(is_sha256(&rebar));
        assert_ne!(high_level, rebar);

        let no_unicode = run_no_unicode_contract().expect("no-Unicode semantic gate");
        assert_eq!(no_unicode, expected_no_unicode_evidence());
        assert!(is_sha256(&no_unicode));
        let age_unicode = run_age_unicode_contract().expect("unicode-age semantic gate");
        assert_eq!(age_unicode, expected_age_unicode_evidence());
        assert!(is_sha256(&age_unicode));
    }

    #[test]
    fn manifest_parser_rejects_non_array_feature_members() {
        let error = parse_declared_features(b"[features]\ndefault = 'std'\n")
            .expect_err("non-array feature must fail closed");
        assert!(error.to_string().contains("not an array"));
    }

    #[test]
    fn disposition_validator_rejects_a_skip_disguised_as_pass() {
        let toolchain = FeatureMatrixToolchain {
            rustc_release: "1.93.0".to_owned(),
            rustc_host: "aarch64-apple-darwin".to_owned(),
            cargo_release: "1.93.0".to_owned(),
            nightly: false,
        };
        let unsupported = CONFIGURATIONS
            .iter()
            .find(|spec| spec.id == "unicode-bool")
            .expect("unicode-bool configuration");
        let forged = FeatureMatrixDisposition::Pass {
            semantic_evidence_sha256: "0".repeat(64),
        };
        validate_disposition(unsupported, &toolchain, &forged)
            .expect_err("unsupported profile cannot claim pass");
    }
}
