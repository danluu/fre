use std::{
    collections::{BTreeMap, BTreeSet},
    env,
    error::Error,
    fs::{self, OpenOptions},
    io::Write as _,
    path::{Path, PathBuf},
};

use fre::{
    AggregateBuilder, AggregatePlanKind, AggregatePlanSelection, AggregateStrategy, RustProfile,
};
use fre_syntax::{CanonicalPattern, CompatibilityProfile, ParseRequest, parse};
use regex_syntax::hir::{Hir, HirKind};
use rust_regex_conformance::{
    CaseReceipt, CorpusMembership, Inventory, MatchKind, SearchKind, SourceFileKind, read_inventory,
};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

const OUTPUT_SCHEMA: &str = "fre.aot.external-regex-1.12.4-development-inventory.v1";
const EXPECTED_UPSTREAM_REVISION: &str = "7b96fdc9d5fe6a0cb4efe30e6689b050493fc1e1";
const EXPECTED_INVENTORY_PAYLOAD: &str =
    "6c5150a2fc66c7262c0ca308fa164cc6fca78de97ae3dfbc948b53c41ca2a263";
const EXPECTED_PREREGISTRATION_SHA256: &str =
    "341afa33a680c4c8a3ba2274675c87a7720da818bb2fcee8333be84f8349b2a2";
const PARTITION_DOMAIN: &[u8] = b"fre.aot.external-regex-1.12.4.partition.v1\0";
const OPTIONS_DOMAIN: &[u8] = b"fre.aot.external-regex-1.12.4.options.v1\0";
const CANDIDATE_DOMAIN: &[u8] = b"fre.aot.external-regex-1.12.4.candidate.v1\0";
const PUBLISHED_PACKAGE_OMISSIONS: [&str; 8] = [
    "README.md",
    "fowler/basic.toml",
    "fowler/dat/README",
    "fowler/dat/basic.dat",
    "fowler/dat/nullsubexpr.dat",
    "fowler/dat/repetition.dat",
    "fowler/nullsubexpr.toml",
    "fowler/repetition.toml",
];

type DynError = Box<dyn Error>;

#[derive(Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct RawSuite {
    #[serde(default, rename = "test")]
    tests: Vec<RawCase>,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
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

#[derive(Debug, Serialize)]
struct Output {
    schema: &'static str,
    preregistration_sha256: &'static str,
    upstream_revision: &'static str,
    upstream_inventory_payload_sha256: &'static str,
    package_root_sha256: String,
    partition: &'static str,
    partition_rule: &'static str,
    payload_sha256: String,
    payload: Payload,
}

#[derive(Debug, Serialize)]
struct Payload {
    authenticated_source_files: Vec<SourceReceipt>,
    authenticated_checkout_inventory_omissions: Vec<SourceReceipt>,
    raw_development_cases: usize,
    prefilter_eligible_cases: usize,
    exact_admitted_cases_before_deduplication: usize,
    exact_refused_cases: usize,
    semantic_candidates: Vec<Candidate>,
    refusals: Vec<Refusal>,
    width_counts: BTreeMap<usize, usize>,
    shape_counts: BTreeMap<String, usize>,
    source_counts: BTreeMap<String, usize>,
}

#[derive(Debug, Serialize)]
struct SourceReceipt {
    path: String,
    bytes: u64,
    sha256: String,
    raw_cases: usize,
}

#[derive(Clone, Debug, Serialize)]
struct Candidate {
    semantic_candidate_sha256: String,
    representative_case_id: String,
    representative_case_sha256: String,
    member_case_ids: Vec<String>,
    member_case_sha256: Vec<String>,
    source_files: Vec<String>,
    source_file_sha256: Vec<String>,
    raw_pattern_sha256: String,
    canonical_pattern_sha256: String,
    semantic_options_sha256: String,
    unicode: bool,
    literal_hex: String,
    literal_sha256: String,
    literal_bytes: usize,
    shape: String,
    search_applicable: bool,
    count_development_applicable: bool,
    count_final_identity_pending: bool,
}

#[derive(Clone, Debug)]
struct Admitted {
    case_id: String,
    case_sha256: String,
    source_file: String,
    source_file_sha256: String,
    raw_pattern_sha256: String,
    canonical_pattern_sha256: String,
    semantic_options_sha256: String,
    unicode: bool,
    literal: Vec<u8>,
    semantic_candidate_sha256: String,
}

#[derive(Debug, Serialize)]
struct Refusal {
    case_id: String,
    case_sha256: String,
    source_file: String,
    reason: String,
}

fn main() -> Result<(), DynError> {
    let arguments = env::args_os().skip(1).collect::<Vec<_>>();
    let [
        package_root,
        inventory_path,
        preregistration_path,
        output_path,
    ] = arguments.as_slice()
    else {
        return Err("usage: PACKAGE_ROOT INVENTORY PREREGISTRATION DEVELOPMENT_OUTPUT_JSON".into());
    };
    let package_root = PathBuf::from(package_root);
    let inventory_path = PathBuf::from(inventory_path);
    let preregistration_path = PathBuf::from(preregistration_path);
    let output_path = PathBuf::from(output_path);
    if output_path.exists() {
        return Err(format!("refusing existing output {}", output_path.display()).into());
    }
    require_file_sha(
        &preregistration_path,
        EXPECTED_PREREGISTRATION_SHA256,
        "preregistration",
    )?;
    authenticate_published_package(&package_root)?;
    let inventory = read_inventory(&inventory_path)?;
    if inventory.payload_sha256 != EXPECTED_INVENTORY_PAYLOAD {
        return Err("checked-in upstream inventory payload changed".into());
    }
    authenticate_testdata(&package_root, &inventory)?;
    let source_hashes = inventory
        .payload
        .source_files
        .iter()
        .map(|source| (source.path.as_str(), source.sha256.as_str()))
        .collect::<BTreeMap<_, _>>();
    let receipts = inventory
        .payload
        .cases
        .iter()
        .map(|case| ((case.source_file.as_str(), case.source_ordinal), case))
        .collect::<BTreeMap<_, _>>();

    let mut raw_development_cases = 0_usize;
    let mut prefilter_eligible_cases = 0_usize;
    let mut admitted = Vec::new();
    let mut refusals = Vec::new();
    for source in &inventory.payload.source_files {
        if is_published_package_omission(&source.path) {
            continue;
        }
        if source.kind != SourceFileKind::RustRegexCorpusToml {
            continue;
        }
        let bytes = fs::read(package_root.join("testdata").join(&source.path))?;
        let suite: RawSuite = toml::from_str(std::str::from_utf8(&bytes)?)?;
        if suite.tests.len() != source.raw_cases {
            return Err(format!("raw case count changed for {}", source.path).into());
        }
        let base = source
            .path
            .strip_suffix(".toml")
            .ok_or("inventory TOML source lacks suffix")?;
        let mut unnamed = 0_usize;
        for (index, raw) in suite.tests.into_iter().enumerate() {
            let ordinal = index.checked_add(1).ok_or("source ordinal overflow")?;
            let name = if raw.name.is_empty() {
                unnamed = unnamed.checked_add(1).ok_or("unnamed counter overflow")?;
                unnamed.to_string()
            } else {
                raw.name.clone()
            };
            let case_id = format!("{base}/{name}");
            let receipt = receipts
                .get(&(source.path.as_str(), ordinal))
                .ok_or("source case has no inventory receipt")?;
            if receipt.id != case_id {
                return Err(format!("case ID changed at {} ordinal {ordinal}", source.path).into());
            }
            let raw_sha256 = sha256(&serde_json::to_vec(&raw)?);
            if raw_sha256 != receipt.case_sha256 {
                return Err(format!("case content hash changed for {case_id}").into());
            }

            // This is the blind boundary: partition from the already
            // authenticated case digest, then drop held-out content before
            // inspecting the pattern or any expected/haystack field.
            if is_heldout(&receipt.case_sha256)? {
                continue;
            }
            raw_development_cases = raw_development_cases
                .checked_add(1)
                .ok_or("development case count overflow")?;
            let source_sha256 = source_hashes
                .get(source.path.as_str())
                .ok_or("source hash missing")?
                .to_string();
            let Some(pattern) = prefilter(receipt, &raw)? else {
                refusals.push(Refusal {
                    case_id,
                    case_sha256: receipt.case_sha256.clone(),
                    source_file: source.path.clone(),
                    reason: prefilter_reason(receipt, &raw),
                });
                continue;
            };
            prefilter_eligible_cases = prefilter_eligible_cases
                .checked_add(1)
                .ok_or("prefilter count overflow")?;
            match authenticate_exact(pattern, receipt.unicode) {
                Ok(exact) => admitted.push(Admitted {
                    case_id,
                    case_sha256: receipt.case_sha256.clone(),
                    source_file: source.path.clone(),
                    source_file_sha256: source_sha256,
                    raw_pattern_sha256: sha256(pattern.as_bytes()),
                    canonical_pattern_sha256: sha256(exact.canonical_pattern.as_bytes()),
                    semantic_options_sha256: exact.semantic_options_sha256,
                    unicode: receipt.unicode,
                    literal: exact.literal,
                    semantic_candidate_sha256: exact.semantic_candidate_sha256,
                }),
                Err(reason) => refusals.push(Refusal {
                    case_id,
                    case_sha256: receipt.case_sha256.clone(),
                    source_file: source.path.clone(),
                    reason,
                }),
            }
        }
    }
    refusals.sort_by(|left, right| {
        (&left.case_sha256, &left.case_id).cmp(&(&right.case_sha256, &right.case_id))
    });
    let exact_admitted_cases_before_deduplication = admitted.len();
    let semantic_candidates = deduplicate(admitted)?;
    let mut width_counts = BTreeMap::new();
    let mut shape_counts = BTreeMap::new();
    let mut source_counts = BTreeMap::new();
    for candidate in &semantic_candidates {
        increment(&mut width_counts, candidate.literal_bytes)?;
        increment(&mut shape_counts, candidate.shape.clone())?;
        for source in &candidate.source_files {
            increment(&mut source_counts, source.clone())?;
        }
    }
    let authenticated_source_files = inventory
        .payload
        .source_files
        .iter()
        .filter(|source| !is_published_package_omission(&source.path))
        .map(|source| SourceReceipt {
            path: source.path.clone(),
            bytes: source.bytes,
            sha256: source.sha256.clone(),
            raw_cases: source.raw_cases,
        })
        .collect::<Vec<_>>();
    let authenticated_checkout_inventory_omissions = inventory
        .payload
        .source_files
        .iter()
        .filter(|source| is_published_package_omission(&source.path))
        .map(|source| SourceReceipt {
            path: source.path.clone(),
            bytes: source.bytes,
            sha256: source.sha256.clone(),
            raw_cases: source.raw_cases,
        })
        .collect::<Vec<_>>();
    if authenticated_checkout_inventory_omissions.len() != PUBLISHED_PACKAGE_OMISSIONS.len() {
        return Err("frozen published-package omission inventory changed".into());
    }
    let package_root_sha256 = package_identity(&authenticated_source_files)?;
    let payload = Payload {
        authenticated_source_files,
        authenticated_checkout_inventory_omissions,
        raw_development_cases,
        prefilter_eligible_cases,
        exact_admitted_cases_before_deduplication,
        exact_refused_cases: refusals.len(),
        semantic_candidates,
        refusals,
        width_counts,
        shape_counts,
        source_counts,
    };
    let payload_sha256 = sha256(&serde_json::to_vec(&payload)?);
    let output = Output {
        schema: OUTPUT_SCHEMA,
        preregistration_sha256: EXPECTED_PREREGISTRATION_SHA256,
        upstream_revision: EXPECTED_UPSTREAM_REVISION,
        upstream_inventory_payload_sha256: EXPECTED_INVENTORY_PAYLOAD,
        package_root_sha256,
        partition: "development",
        partition_rule: "sha256(domain || upstream-case-sha256-bytes)[0] >= 64",
        payload_sha256,
        payload,
    };
    let mut bytes = serde_json::to_vec_pretty(&output)?;
    bytes.push(b'\n');
    if let Some(parent) = output_path.parent() {
        fs::create_dir_all(parent)?;
    }
    let mut output_file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(&output_path)?;
    output_file.write_all(&bytes)?;
    output_file.sync_all()?;
    println!("output={}", output_path.display());
    println!("sha256={}", sha256(&bytes));
    println!(
        "semantic_candidates={}",
        output.payload.semantic_candidates.len()
    );
    Ok(())
}

fn authenticate_published_package(package_root: &Path) -> Result<(), DynError> {
    let vcs: serde_json::Value =
        serde_json::from_slice(&fs::read(package_root.join(".cargo_vcs_info.json"))?)?;
    let dirty = vcs
        .pointer("/git/dirty")
        .and_then(serde_json::Value::as_bool);
    if vcs.pointer("/git/sha1").and_then(serde_json::Value::as_str)
        != Some(EXPECTED_UPSTREAM_REVISION)
        || dirty == Some(true)
    {
        return Err("published package VCS identity mismatch".into());
    }
    let manifest: toml::Value =
        toml::from_str(&fs::read_to_string(package_root.join("Cargo.toml.orig"))?)?;
    if manifest
        .get("package")
        .and_then(|package| package.get("version"))
        .and_then(toml::Value::as_str)
        != Some("1.12.4")
    {
        return Err("published package version mismatch".into());
    }
    Ok(())
}

fn authenticate_testdata(package_root: &Path, inventory: &Inventory) -> Result<(), DynError> {
    let testdata = package_root.join("testdata");
    let mut actual = Vec::new();
    collect_files(&testdata, &testdata, &mut actual)?;
    actual.sort();
    let expected = inventory
        .payload
        .source_files
        .iter()
        .filter(|source| !is_published_package_omission(&source.path))
        .map(|source| source.path.clone())
        .collect::<Vec<_>>();
    if actual != expected {
        return Err("published testdata file set differs from inventory".into());
    }
    for source in &inventory.payload.source_files {
        if is_published_package_omission(&source.path) {
            if testdata.join(&source.path).exists() {
                return Err(format!(
                    "published package unexpectedly contains frozen packaging omission {}",
                    source.path
                )
                .into());
            }
            continue;
        }
        let path = testdata.join(&source.path);
        let metadata = fs::symlink_metadata(&path)?;
        if !metadata.file_type().is_file()
            || metadata.len() != source.bytes
            || sha256(&fs::read(&path)?) != source.sha256
        {
            return Err(format!("source receipt mismatch for {}", source.path).into());
        }
    }
    Ok(())
}

fn is_published_package_omission(path: &str) -> bool {
    PUBLISHED_PACKAGE_OMISSIONS.binary_search(&path).is_ok()
}

fn collect_files(root: &Path, directory: &Path, output: &mut Vec<String>) -> Result<(), DynError> {
    let mut entries = fs::read_dir(directory)?.collect::<Result<Vec<_>, _>>()?;
    entries.sort_by_key(std::fs::DirEntry::file_name);
    for entry in entries {
        let file_type = entry.file_type()?;
        if file_type.is_symlink() {
            return Err(format!("symlink in testdata: {}", entry.path().display()).into());
        }
        if file_type.is_dir() {
            collect_files(root, &entry.path(), output)?;
        } else if file_type.is_file() {
            output.push(
                entry
                    .path()
                    .strip_prefix(root)?
                    .to_str()
                    .ok_or("non-UTF8 testdata path")?
                    .replace(std::path::MAIN_SEPARATOR, "/"),
            );
        } else {
            return Err(format!("unsupported testdata entry: {}", entry.path().display()).into());
        }
    }
    Ok(())
}

fn is_heldout(case_sha256: &str) -> Result<bool, DynError> {
    let digest = decode_sha256(case_sha256)?;
    let mut hasher = Sha256::new();
    hasher.update(PARTITION_DOMAIN);
    hasher.update(digest);
    Ok(hasher.finalize()[0] < 64)
}

fn prefilter<'case>(
    receipt: &CaseReceipt,
    raw: &'case RawCase,
) -> Result<Option<&'case str>, DynError> {
    if receipt.corpus_membership != CorpusMembership::RustRegexSuite
        || receipt.pattern_count != 1
        || !receipt.compiles
        || receipt.anchored
        || receipt.bounded_search
        || receipt.case_insensitive
        || receipt.custom_line_terminator
        || receipt.match_limit.is_some()
        || receipt.match_kind != MatchKind::LeftmostFirst
        || receipt.search_kind != SearchKind::Leftmost
    {
        return Ok(None);
    }
    let Some(pattern) = raw.regex.as_str() else {
        return Ok(None);
    };
    Ok(Some(pattern))
}

fn prefilter_reason(receipt: &CaseReceipt, raw: &RawCase) -> String {
    if receipt.corpus_membership != CorpusMembership::RustRegexSuite {
        "not-rust-regex-suite"
    } else if receipt.pattern_count != 1 || raw.regex.as_str().is_none() {
        "not-one-string-pattern"
    } else if !receipt.compiles {
        "declared-compile-rejection"
    } else if receipt.anchored {
        "anchored-search-policy"
    } else if receipt.bounded_search {
        "bounded-search-policy"
    } else if receipt.case_insensitive {
        "case-insensitive"
    } else if receipt.custom_line_terminator {
        "custom-line-terminator"
    } else if receipt.match_limit.is_some() {
        "bounded-match-limit"
    } else if receipt.match_kind != MatchKind::LeftmostFirst {
        "non-leftmost-first-match-kind"
    } else if receipt.search_kind != SearchKind::Leftmost {
        "non-leftmost-search-kind"
    } else {
        "prefilter-refusal"
    }
    .to_string()
}

struct Exact {
    literal: Vec<u8>,
    canonical_pattern: String,
    semantic_options_sha256: String,
    semantic_candidate_sha256: String,
}

fn authenticate_exact(pattern: &str, unicode: bool) -> Result<Exact, String> {
    let mut profile = RustProfile::regex_1_12_4();
    profile.options.unicode = unicode;
    profile.options.case_insensitive = false;
    let owner = AggregateBuilder::new(pattern.to_string())
        .profile(profile.clone())
        .unicode(unicode)
        .case_insensitive(false)
        .plan_selection(AggregatePlanSelection::ForceExactLiteral)
        .strategy(AggregateStrategy::ReverseSequentialRows)
        .build_count()
        .map_err(|error| format!("fre-force-exact-refused:{error}"))?;
    if owner.build_report().plan != AggregatePlanKind::ExactLiteral {
        return Err("fre-force-exact-selected-other-plan".to_string());
    }
    let parsed = parse(ParseRequest::rust(
        pattern.to_string(),
        CompatibilityProfile::RustBytes(profile.clone()),
    ))
    .map_err(|error| format!("fre-syntax-reparse-refused:{error}"))?;
    let CanonicalPattern::Rust(parsed) = parsed.pattern else {
        return Err("fre-syntax-returned-non-rust-pattern".to_string());
    };
    let mut literal = Vec::new();
    exact_hir_bytes(&parsed.hir, &mut literal)
        .map_err(|()| "fre-exact-hir-reconstruction-refused".to_string())?;
    if literal.is_empty() {
        return Err("empty-literal".to_string());
    }
    if literal.len() > 32 {
        return Err("literal-width-over-32".to_string());
    }
    let canonical_pattern = canonical_pattern(&literal);
    let canonical_owner = AggregateBuilder::new(canonical_pattern.clone())
        .profile(RustProfile::regex_1_12_4())
        .unicode(false)
        .case_insensitive(false)
        .plan_selection(AggregatePlanSelection::ForceExactLiteral)
        .strategy(AggregateStrategy::ReverseSequentialRows)
        .build_count()
        .map_err(|error| format!("canonical-byte-spelling-refused:{error}"))?;
    if canonical_owner.build_report().plan != AggregatePlanKind::ExactLiteral {
        return Err("canonical-byte-spelling-selected-other-plan".to_string());
    }
    let canonical_profile = CompatibilityProfile::RustBytes(RustProfile::regex_1_12_4());
    let canonical_parsed = parse(ParseRequest::rust(
        canonical_pattern.clone(),
        canonical_profile,
    ))
    .map_err(|error| format!("canonical-byte-spelling-reparse-refused:{error}"))?;
    let CanonicalPattern::Rust(canonical_parsed) = canonical_parsed.pattern else {
        return Err("canonical-spelling-returned-non-rust-pattern".to_string());
    };
    let mut rebuilt = Vec::new();
    exact_hir_bytes(&canonical_parsed.hir, &mut rebuilt)
        .map_err(|()| "canonical-byte-spelling-not-exact".to_string())?;
    if rebuilt != literal {
        return Err("canonical-byte-spelling-literal-mismatch".to_string());
    }
    let profile_identity = profile.identity_string();
    let semantic_options_sha256 = sha256_parts(OPTIONS_DOMAIN, &[profile_identity.as_bytes()]);
    let literal_sha256 = sha256(&literal);
    let semantic_candidate_sha256 = sha256_parts(
        CANDIDATE_DOMAIN,
        &[
            &decode_sha256(&semantic_options_sha256).map_err(|error| error.to_string())?,
            &decode_sha256(&literal_sha256).map_err(|error| error.to_string())?,
        ],
    );
    Ok(Exact {
        literal,
        canonical_pattern,
        semantic_options_sha256,
        semantic_candidate_sha256,
    })
}

fn exact_hir_bytes(hir: &Hir, output: &mut Vec<u8>) -> Result<(), ()> {
    match hir.kind() {
        HirKind::Empty => Ok(()),
        HirKind::Literal(literal) => {
            output.extend_from_slice(&literal.0);
            Ok(())
        }
        HirKind::Capture(capture) => exact_hir_bytes(&capture.sub, output),
        HirKind::Concat(parts) => {
            for part in parts {
                exact_hir_bytes(part, output)?;
            }
            Ok(())
        }
        _ => Err(()),
    }
}

fn canonical_pattern(literal: &[u8]) -> String {
    let mut pattern = String::with_capacity(6 + literal.len() * 4);
    pattern.push_str("(?-u:");
    for byte in literal {
        pattern.push_str("\\x");
        pattern.push(hex_digit(byte >> 4));
        pattern.push(hex_digit(byte & 0x0f));
    }
    pattern.push(')');
    pattern
}

fn deduplicate(admitted: Vec<Admitted>) -> Result<Vec<Candidate>, DynError> {
    let mut groups = BTreeMap::<String, Vec<Admitted>>::new();
    for row in admitted {
        groups
            .entry(row.semantic_candidate_sha256.clone())
            .or_default()
            .push(row);
    }
    let mut candidates = Vec::with_capacity(groups.len());
    for (identity, mut rows) in groups {
        rows.sort_by(|left, right| {
            (&left.case_sha256, &left.case_id).cmp(&(&right.case_sha256, &right.case_id))
        });
        let first = rows.first().ok_or("empty semantic candidate group")?;
        if rows.iter().any(|row| {
            row.literal != first.literal
                || row.semantic_options_sha256 != first.semantic_options_sha256
        }) {
            return Err("semantic candidate hash collision".into());
        }
        let source_files = rows
            .iter()
            .map(|row| row.source_file.clone())
            .collect::<BTreeSet<_>>()
            .into_iter()
            .collect();
        let source_file_sha256 = rows
            .iter()
            .map(|row| row.source_file_sha256.clone())
            .collect::<BTreeSet<_>>()
            .into_iter()
            .collect();
        candidates.push(Candidate {
            semantic_candidate_sha256: identity,
            representative_case_id: first.case_id.clone(),
            representative_case_sha256: first.case_sha256.clone(),
            member_case_ids: rows.iter().map(|row| row.case_id.clone()).collect(),
            member_case_sha256: rows.iter().map(|row| row.case_sha256.clone()).collect(),
            source_files,
            source_file_sha256,
            raw_pattern_sha256: first.raw_pattern_sha256.clone(),
            canonical_pattern_sha256: first.canonical_pattern_sha256.clone(),
            semantic_options_sha256: first.semantic_options_sha256.clone(),
            unicode: first.unicode,
            literal_hex: hex(&first.literal),
            literal_sha256: sha256(&first.literal),
            literal_bytes: first.literal.len(),
            shape: shape(&first.literal),
            search_applicable: true,
            count_development_applicable: !first.unicode,
            count_final_identity_pending: !first.unicode,
        });
    }
    Ok(candidates)
}

fn shape(literal: &[u8]) -> String {
    if literal.iter().any(|byte| !(0x20..=0x7e).contains(byte)) {
        return "binary".to_string();
    }
    if literal.iter().all(|byte| *byte == literal[0]) {
        return "uniform".to_string();
    }
    if minimum_period(literal) < literal.len() {
        return "periodic".to_string();
    }
    let distinct = literal.iter().copied().collect::<BTreeSet<_>>().len();
    if distinct < literal.len() {
        "repeated".to_string()
    } else {
        "distinct".to_string()
    }
}

fn minimum_period(literal: &[u8]) -> usize {
    (1..=literal.len())
        .find(|period| {
            literal
                .iter()
                .enumerate()
                .all(|(index, byte)| *byte == literal[index % period])
        })
        .unwrap_or(literal.len())
}

fn increment<K: Ord>(counts: &mut BTreeMap<K, usize>, key: K) -> Result<(), DynError> {
    let value = counts.entry(key).or_default();
    *value = value.checked_add(1).ok_or("count overflow")?;
    Ok(())
}

fn package_identity(sources: &[SourceReceipt]) -> Result<String, DynError> {
    let mut hasher = Sha256::new();
    hasher.update(b"fre.aot.external-regex-1.12.4.package.v1\0");
    for source in sources {
        hasher.update(u64::try_from(source.path.len())?.to_le_bytes());
        hasher.update(source.path.as_bytes());
        hasher.update(decode_sha256(&source.sha256)?);
        hasher.update(source.bytes.to_le_bytes());
    }
    Ok(hex(&hasher.finalize()))
}

fn require_file_sha(path: &Path, expected: &str, label: &str) -> Result<(), DynError> {
    if sha256(&fs::read(path)?) != expected {
        return Err(format!("{label} SHA-256 mismatch").into());
    }
    Ok(())
}

fn sha256(bytes: &[u8]) -> String {
    hex(&Sha256::digest(bytes))
}

fn sha256_parts(domain: &[u8], parts: &[&[u8]]) -> String {
    let mut hasher = Sha256::new();
    hasher.update(domain);
    for part in parts {
        hasher.update(
            u64::try_from(part.len())
                .expect("bounded hash part")
                .to_le_bytes(),
        );
        hasher.update(part);
    }
    hex(&hasher.finalize())
}

fn decode_sha256(value: &str) -> Result<[u8; 32], DynError> {
    if value.len() != 64 {
        return Err("SHA-256 is not 64 hexadecimal digits".into());
    }
    let mut bytes = [0_u8; 32];
    for (index, pair) in value.as_bytes().chunks_exact(2).enumerate() {
        bytes[index] = (decode_nibble(pair[0])? << 4) | decode_nibble(pair[1])?;
    }
    Ok(bytes)
}

fn decode_nibble(byte: u8) -> Result<u8, DynError> {
    match byte {
        b'0'..=b'9' => Ok(byte - b'0'),
        b'a'..=b'f' => Ok(byte - b'a' + 10),
        _ => Err("SHA-256 contains non-lowercase-hex byte".into()),
    }
}

fn hex(bytes: &[u8]) -> String {
    let mut output = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        output.push(hex_digit(byte >> 4));
        output.push(hex_digit(byte & 0x0f));
    }
    output
}

fn hex_digit(nibble: u8) -> char {
    match nibble {
        0..=9 => char::from(b'0' + nibble),
        10..=15 => char::from(b'a' + (nibble - 10)),
        _ => unreachable!(),
    }
}
