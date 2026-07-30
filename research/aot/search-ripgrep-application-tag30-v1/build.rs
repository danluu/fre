#![recursion_limit = "256"]

use std::{
    collections::BTreeSet,
    env,
    fmt::Write as _,
    fs,
    path::{Path, PathBuf},
};

use fre::{PortableBuilder, RustProfile};
use fre_aot_compiler::{
    LinuxAarch64ExactSearchManifestV1, LinuxAarch64SearchCompilePolicyV1,
    LinuxSearchCompileErrorV1, LinuxSearchSpanFinalImageGlueLimitsV1,
    MacosAarch64ExactSearchManifestV1, SearchCompileErrorV1, SearchCompilePolicyV1,
    SearchSpanFinalImageGlueLimitsV1, build_linux_static_search_span_expectation_v1,
    build_static_search_span_expectation_v1, plan_and_compile_linux_aarch64_exact_search_v1,
    plan_and_compile_macos_aarch64_exact_search_v1,
    publish_linux_search_span_family_qualification_final_image_glue_v1,
    publish_search_span_family_qualification_final_image_glue_v1,
};
use fre_jit_aarch64::{EmitError, UnsupportedReason};
use fre_kernel_ir::Span;
use serde_json::{Value, json};
use sha2::{Digest, Sha256};

const BINARY: &str = "fre-search-tag30-ripgrep-application-runner";
const IDENTITY_ENV: &str = "FRE_SEARCH_TAG30_APPLICATION_IDENTITY";
const REVISION_ENV: &str = "FRE_SEARCH_TAG30_APPLICATION_RUNNER_REVISION";
const SOURCE_ARCHIVE_ENV: &str = "FRE_SEARCH_TAG30_APPLICATION_SOURCE_ARCHIVE_SHA256";
const UNSEALED_ENV: &str = "FRE_SEARCH_TAG30_APPLICATION_ALLOW_UNSEALED_ARTIFACT_BUILD";
const CANDIDATE_MANIFEST_ENV: &str = "FRE_SEARCH_TAG30_APPLICATION_OBJECT_CANDIDATES";
const LITERAL_DISPOSITIONS_ENV: &str = "FRE_SEARCH_TAG30_APPLICATION_LITERAL_DISPOSITIONS";
const IDENTITY_SCHEMA: &str = "fre.aot.search-tag30-ripgrep-application-runner-identity.v1";
const APPLICATION_FIXTURE_SCHEMA_V2: &str = "fre.aot.search-ripgrep-application-fixtures.v2";
const APPLICATION_FIXTURE_MANIFEST_SHA256_V2: &str =
    "b20181470c604d01d2ec236259293cfcb6e5eff145bcd3e4daa91554c8cebcca";
const CANONICAL_SOURCE_CONSTRUCTION: &str = "canonical-byte-escaped-exact";
const MAXIMUM_CANDIDATE_MANIFEST_BYTES: u64 = 1 << 20;
const MAXIMUM_LITERAL_DISPOSITIONS_BYTES: u64 = 4 << 20;
const MAXIMUM_CANDIDATES: usize = 1 << 10;
const MAXIMUM_LITERAL_DISPOSITIONS: usize = 2 << 10;
const SOURCE_DOMAIN: &[u8] = b"FRE-SEARCH-TAG30-RIPGREP-APPLICATION-RUNNER-SOURCE\0\x01";
const GLUE_SYMBOL_PREFIX: &str = "fre_aot_search_span_glue_v1_";
const LITERAL_DISPOSITIONS_SCHEMA: &str =
    "fre.aot.search-tag30-application-literal-dispositions.v1";
const REFUSAL_RECEIPT_SCHEMA: &str = "fre.aot.search-tag30-structural-refusal-compile-receipt.v1";
const PRIVATE_FAMILY_SOURCE: &str =
    "../../../crates/fre-aot-static-runtime/src/search_support/private_rows.rs";
const COMPILER_IDENTITY_DOMAIN: &[u8] = b"FRE-SEARCH-TAG30-COMPILER-SOURCE-IDENTITY\0\x01";

#[derive(Clone, Debug, Eq, PartialEq)]
struct Candidate {
    semantic_candidate_sha256: String,
    source: Vec<u8>,
    literal: Vec<u8>,
    literal_hex: String,
    literal_sha256: String,
}

#[derive(Debug)]
struct CandidateManifest {
    schema: String,
    sha256: String,
    payload_sha256: String,
    canonical_byte_escaped_sources: bool,
    candidates: Vec<Candidate>,
}

#[derive(Debug)]
struct LiteralDispositions {
    sha256: String,
    payload_sha256: String,
    literal_count: usize,
    refusals: Vec<Candidate>,
}

struct BuiltCandidate {
    implementation: Vec<u8>,
    glue: Vec<u8>,
    compile_receipt: Vec<u8>,
    compile_identity: [u8; 32],
    manifest_identity: [u8; 32],
    implementation_symbols: [String; 3],
    glue_symbol: String,
}

#[derive(Debug)]
struct StagedCandidate {
    candidate: Candidate,
    compile_identity: String,
    compile_receipt_sha256: String,
    compile_receipt_basename: String,
    implementation_object_sha256: String,
    glue_object_sha256: String,
    implementation_object_basename: String,
    glue_object_basename: String,
    implementation_symbols: [String; 3],
    glue_symbol: String,
}

#[derive(Debug)]
struct StagedRefusal {
    candidate: Candidate,
    compile_receipt_sha256: String,
    compile_receipt_basename: String,
}

#[allow(
    clippy::too_many_lines,
    reason = "the build transaction deliberately keeps identity validation, object emission, and exact linker publication in one auditable sequence"
)]
fn main() {
    println!("cargo:rerun-if-env-changed={IDENTITY_ENV}");
    println!("cargo:rerun-if-env-changed={REVISION_ENV}");
    println!("cargo:rerun-if-env-changed={SOURCE_ARCHIVE_ENV}");
    println!("cargo:rerun-if-env-changed={UNSEALED_ENV}");
    println!("cargo:rerun-if-env-changed={CANDIDATE_MANIFEST_ENV}");
    println!("cargo:rerun-if-env-changed={LITERAL_DISPOSITIONS_ENV}");
    println!("cargo:rerun-if-changed=runner-source-files.txt");
    println!("cargo:rerun-if-changed={PRIVATE_FAMILY_SOURCE}");
    for source in source_manifest().expect("runner source manifest") {
        println!("cargo:rerun-if-changed={source}");
    }

    let output = required_path("OUT_DIR");
    let source_identity = runner_source_identity().expect("runner source identity");
    let source_identity_hex = hex(&source_identity);
    fs::write(
        output.join("runner-source-sha256.txt"),
        format!("{source_identity_hex}\n"),
    )
    .expect("runner source identity receipt");
    println!("cargo:warning=runner source-set sha256={source_identity_hex}");
    let Some(identity_path) = env::var_os(IDENTITY_ENV).map(PathBuf::from) else {
        write_scaffold(&output).expect("write selector-neutral runner scaffold");
        println!(
            "cargo:warning=external static runner is selector-neutral; set {IDENTITY_ENV} to build linked artifacts"
        );
        return;
    };
    println!("cargo:rerun-if-changed={}", identity_path.display());
    let identity_bytes = regular_file(&identity_path, 1 << 20).expect("bounded identity file");
    let identity_sha256 = sha256(&identity_bytes);
    let identity: Value = serde_json::from_slice(&identity_bytes).expect("identity JSON");
    let identity_schema = identity
        .get("schema")
        .and_then(Value::as_str)
        .expect("static runner identity schema");
    require(
        identity_schema == IDENTITY_SCHEMA,
        "tag30 application identity schema changed",
    );
    let fixture_manifest_sha256 =
        path_str(&identity, &["external_evidence", "fixture_manifest_sha256"]);
    let fixture_manifest_schema =
        path_str(&identity, &["external_evidence", "fixture_manifest_schema"]);
    require(
        fixture_manifest_schema == APPLICATION_FIXTURE_SCHEMA_V2
            && fixture_manifest_sha256 == APPLICATION_FIXTURE_MANIFEST_SHA256_V2,
        "fixture manifest identity changed",
    );
    require(
        identity.pointer("/emitter/llvm").and_then(Value::as_bool) == Some(false),
        "LLVM is not admissible",
    );
    let backend_tag = path_u16(&identity, &["static_pipeline", "backend_tag"]);
    let backend_name = path_str(&identity, &["static_pipeline", "backend_name"]);
    require(!backend_name.is_empty(), "backend name is empty");
    require(
        backend_tag == 30
            && backend_name == "AsimdV17"
            && path_u16(&identity, &["emitter", "backend_tag"]) == 30
            && path_str(&identity, &["emitter", "backend"]) == "AsimdV17"
            && path_u16(&identity, &["emitter", "candidate_policy"]) == 15
            && path_str(&identity, &["emitter", "aot_magic_hex"]) == "465245413634001e"
            && identity
                .pointer("/emitter/authorization")
                .and_then(Value::as_bool)
                == Some(false),
        "emitter and static candidate identities differ",
    );
    let family_selector = path_u16(&identity, &["auto_routing", "family_selector"]);
    let minimum_literal_bytes = path_u32(&identity, &["auto_routing", "minimum_literal_bytes"]);
    let maximum_literal_bytes = path_u32(&identity, &["auto_routing", "maximum_literal_bytes"]);
    let minimum_window_bytes = path_u32(&identity, &["auto_routing", "minimum_window_bytes"]);
    let portable_prefix_candidate_starts = path_u32(
        &identity,
        &["auto_routing", "portable_prefix_candidate_starts"],
    );
    let plan_identity = path_str(&identity, &["auto_routing", "plan_identity"]);
    let analyzer_identity = path_str(&identity, &["auto_routing", "analyzer_identity"]);
    let evidence_identity = path_str(&identity, &["auto_routing", "evidence_identity"]);
    let private_authorization_identity = path_str(
        &identity,
        &["auto_routing", "private_family_authorization_identity"],
    );
    let expected_private_family_source_sha256 =
        path_str(&identity, &["private_family", "source_sha256"]);
    let private_family_source = regular_file(Path::new(PRIVATE_FAMILY_SOURCE), 1 << 18)
        .expect("bounded private family source");
    let private_family_source_sha256 = hex(&sha256(&private_family_source));
    let application_contract_identity = path_str(&identity, &["application", "contract_sha256"]);
    require(
        is_hex(plan_identity, 64)
            && is_hex(analyzer_identity, 64)
            && is_hex(evidence_identity, 64)
            && is_hex(private_authorization_identity, 64)
            && is_hex(expected_private_family_source_sha256, 64)
            && expected_private_family_source_sha256 == private_family_source_sha256
            && is_hex(application_contract_identity, 64),
        "automatic routing qualification identity is malformed",
    );
    require(
        family_selector == 13
            && minimum_literal_bytes == 6
            && maximum_literal_bytes == 32
            && minimum_window_bytes == 65_536
            && portable_prefix_candidate_starts == 256,
        "family width envelope differs from the evidence scope",
    );
    let candidate_manifest_path = PathBuf::from(
        env::var_os(CANDIDATE_MANIFEST_ENV)
            .unwrap_or_else(|| panic!("linked builds require {CANDIDATE_MANIFEST_ENV}")),
    );
    println!(
        "cargo:rerun-if-changed={}",
        candidate_manifest_path.display()
    );
    let candidate_manifest = load_candidate_manifest(
        &candidate_manifest_path,
        &identity,
        minimum_literal_bytes,
        maximum_literal_bytes,
    )
    .expect("authenticated object-candidate manifest");
    let literal_dispositions_path = PathBuf::from(
        env::var_os(LITERAL_DISPOSITIONS_ENV)
            .unwrap_or_else(|| panic!("linked builds require {LITERAL_DISPOSITIONS_ENV}")),
    );
    println!(
        "cargo:rerun-if-changed={}",
        literal_dispositions_path.display()
    );
    let literal_dispositions = load_literal_dispositions(
        &literal_dispositions_path,
        &candidate_manifest,
        minimum_literal_bytes,
        maximum_literal_bytes,
    )
    .expect("authenticated literal dispositions");
    require(
        literal_dispositions.sha256
            == path_str(&identity, &["literal_dispositions", "manifest_sha256"])
            && literal_dispositions.payload_sha256
                == path_str(&identity, &["literal_dispositions", "payload_sha256"])
            && literal_dispositions.literal_count
                == path_usize(&identity, &["literal_dispositions", "literal_count"]),
        "literal-dispositions identity differs from the sealed identity",
    );
    require(
        identity
            .pointer("/auto_routing/full_window_preflight_authoritative")
            .and_then(Value::as_bool)
            == Some(true)
            && identity
                .pointer("/state/production_authority")
                .and_then(Value::as_bool)
                == Some(false)
            && identity
                .pointer("/state/rebar_accepted_as_input")
                .and_then(Value::as_bool)
                == Some(false),
        "automatic routing policy is incomplete",
    );
    let timing_permitted = identity
        .pointer("/state/development_timing_permitted")
        .and_then(Value::as_bool)
        .expect("development timing state");
    if timing_permitted {
        let private_source_text =
            std::str::from_utf8(&private_family_source).expect("private family source UTF-8");
        require(
            private_source_text
                .matches("SourceQualifiedStaticSearchSpanFamilyV1::private_qualification(")
                .count()
                == 2,
            "timing-sealed build lacks both target-conditional private family rows",
        );
    }
    require(
        identity
            .pointer("/state/heldout_materialized")
            .and_then(Value::as_bool)
            == Some(false),
        "heldout materialization is forbidden",
    );
    let unsealed = env::var(UNSEALED_ENV).as_deref() == Ok("1");
    require(
        timing_permitted || unsealed,
        "identity is not timing-sealed; explicit unsealed artifact mode is required",
    );
    if timing_permitted {
        require(
            identity
                .pointer("/state/blocker")
                .is_some_and(Value::is_null)
                && identity
                    .pointer("/state/bindings_complete")
                    .and_then(Value::as_bool)
                    == Some(true)
                && identity
                    .pointer("/state/application_qualification_authority")
                    .and_then(Value::as_bool)
                    == Some(true),
            "timing-sealed identity retains a blocker",
        );
    }

    let revision = env::var(REVISION_ENV).expect("runner revision");
    require(
        is_hex(&revision, 40),
        "runner revision is not a full Git SHA",
    );
    if let Some(expected) = identity
        .pointer("/runner/source_commit")
        .and_then(Value::as_str)
    {
        require(
            expected == revision,
            "runner revision differs from identity",
        );
    } else {
        require(unsealed, "sealed build lacks runner source commit");
    }
    if let Some(expected) = identity
        .pointer("/runner/source_set_sha256")
        .and_then(Value::as_str)
    {
        require(
            expected == hex(&source_identity),
            "runner source-set identity differs",
        );
    } else {
        require(unsealed, "sealed build lacks runner source-set identity");
    }
    let source_archive_sha256 =
        env::var(SOURCE_ARCHIVE_ENV).expect("application source archive SHA-256");
    require(
        is_hex(&source_archive_sha256, 64)
            && identity
                .pointer("/runner/source_archive_sha256")
                .and_then(Value::as_str)
                == Some(source_archive_sha256.as_str()),
        "application source archive identity differs",
    );

    let target_arch = env::var("CARGO_CFG_TARGET_ARCH").expect("target arch");
    let target_os = env::var("CARGO_CFG_TARGET_OS").expect("target OS");
    require(target_arch == "aarch64", "runner requires AArch64");
    require(
        matches!(target_os.as_str(), "macos" | "linux"),
        "runner requires macOS or Linux",
    );

    let compiler_identity = identity
        .pointer("/static_pipeline/compiler_identity")
        .and_then(Value::as_str)
        .expect("application compiler identity");
    require(
        is_hex(compiler_identity, 64)
            && compiler_identity == compiler_source_identity(&revision, &source_archive_sha256),
        "application compiler source identity differs",
    );
    let platform_key = if target_os == "macos" {
        "macos_aarch64"
    } else {
        "linux_aarch64"
    };
    let expected_manifest_identity = identity
        .pointer(&format!(
            "/platform_artifacts/{platform_key}/manifest_identity"
        ))
        .and_then(Value::as_str);
    if expected_manifest_identity.is_none() {
        require(unsealed, "sealed build lacks platform manifest identity");
    }
    let mut generated = String::new();
    generated.push_str(
        "#[derive(Clone, Copy, Debug)]\npub(crate) struct CandidateIdentity { pub(crate) semantic_candidate_sha256: &'static str, pub(crate) literal_hex: &'static str, pub(crate) implementation_sha256: &'static str, pub(crate) glue_sha256: &'static str }\n",
    );
    writeln!(generated, "pub(crate) const LINKED: bool = true;").unwrap();
    writeln!(
        generated,
        "pub(crate) const TIMING_PERMITTED: bool = {timing_permitted};"
    )
    .unwrap();
    writeln!(
        generated,
        "pub(crate) const BACKEND_TAG: u16 = {backend_tag};"
    )
    .unwrap();
    writeln!(
        generated,
        "pub(crate) const BACKEND_NAME: &str = {backend_name:?};"
    )
    .unwrap();
    writeln!(
        generated,
        "pub(crate) const FAMILY_SELECTOR: u16 = {family_selector};"
    )
    .unwrap();
    writeln!(
        generated,
        "pub(crate) const MINIMUM_WINDOW_BYTES: usize = {minimum_window_bytes};"
    )
    .unwrap();
    writeln!(
        generated,
        "pub(crate) const PORTABLE_PREFIX_CANDIDATE_STARTS: usize = {portable_prefix_candidate_starts};"
    )
    .unwrap();
    writeln!(
        generated,
        "pub(crate) const PLAN_IDENTITY: &str = {plan_identity:?};"
    )
    .unwrap();
    writeln!(
        generated,
        "pub(crate) const ANALYZER_IDENTITY: &str = {analyzer_identity:?};"
    )
    .unwrap();
    writeln!(
        generated,
        "pub(crate) const EVIDENCE_IDENTITY: &str = {evidence_identity:?};"
    )
    .unwrap();
    writeln!(
        generated,
        "pub(crate) const PRIVATE_AUTHORIZATION_IDENTITY: &str = {private_authorization_identity:?};"
    )
    .unwrap();
    writeln!(
        generated,
        "pub(crate) const APPLICATION_CONTRACT_IDENTITY: &str = {application_contract_identity:?};"
    )
    .unwrap();
    writeln!(
        generated,
        "pub(crate) const IDENTITY_SHA256: &str = {:?};",
        hex(&identity_sha256)
    )
    .unwrap();
    writeln!(
        generated,
        "pub(crate) const RUNNER_SOURCE_SHA256: &str = {:?};",
        hex(&source_identity)
    )
    .unwrap();
    writeln!(
        generated,
        "pub(crate) const OBJECT_CANDIDATE_MANIFEST_SCHEMA: &str = {:?};",
        candidate_manifest.schema
    )
    .unwrap();
    writeln!(
        generated,
        "pub(crate) const OBJECT_CANDIDATE_MANIFEST_SHA256: &str = {:?};",
        candidate_manifest.sha256
    )
    .unwrap();
    writeln!(
        generated,
        "pub(crate) const LITERAL_DISPOSITIONS_SHA256: &str = {:?};",
        literal_dispositions.sha256
    )
    .unwrap();
    writeln!(
        generated,
        "pub(crate) const FIXTURE_MANIFEST_SCHEMA: &str = {fixture_manifest_schema:?};"
    )
    .unwrap();
    writeln!(
        generated,
        "pub(crate) const FIXTURE_MANIFEST_SHA256: &str = {fixture_manifest_sha256:?};"
    )
    .unwrap();
    writeln!(
        generated,
        "pub(crate) const CANONICAL_BYTE_ESCAPED_SOURCES: bool = {};",
        candidate_manifest.canonical_byte_escaped_sources
    )
    .unwrap();
    generated.push_str("#[allow(unsafe_code)]\nunsafe extern \"C\" {\n");

    let mut built_candidates = Vec::new();
    let mut emitted_manifest_identity = None;
    let mut compile_identities = BTreeSet::new();
    let mut compile_receipts = BTreeSet::new();
    let mut implementation_objects = BTreeSet::new();
    let mut glue_objects = BTreeSet::new();
    let mut glue_symbols = BTreeSet::new();
    for (index, candidate) in candidate_manifest.candidates.iter().enumerate() {
        let built = if target_os == "macos" {
            build_macos(candidate, backend_tag, family_selector)
        } else {
            build_linux(candidate, backend_tag, family_selector)
        };
        let built_manifest_identity = hex(&built.manifest_identity);
        if let Some(expected) = expected_manifest_identity {
            require(
                expected == built_manifest_identity,
                "emitted manifest identity differs from sealed platform identity",
            );
        }
        if let Some(first) = &emitted_manifest_identity {
            require(
                first == &built_manifest_identity,
                "candidate manifests do not share one identity",
            );
        } else {
            emitted_manifest_identity = Some(built_manifest_identity);
        }
        let implementation_object_basename = format!("external-search-{index}-implementation.o");
        let glue_object_basename = format!("external-search-{index}-family-glue.o");
        let compile_receipt_basename = format!("external-search-{index}-compile-receipt.bin");
        let implementation_path = output.join(&implementation_object_basename);
        let glue_path = output.join(&glue_object_basename);
        let compile_receipt_path = output.join(&compile_receipt_basename);
        fs::write(&implementation_path, &built.implementation).expect("implementation object");
        fs::write(&glue_path, &built.glue).expect("family glue object");
        fs::write(&compile_receipt_path, &built.compile_receipt).expect("compiler receipt");
        println!(
            "cargo:rustc-link-arg-bin={BINARY}={}",
            implementation_path.display()
        );
        println!("cargo:rustc-link-arg-bin={BINARY}={}", glue_path.display());
        writeln!(
            generated,
            "    #[link_name = {:?}] fn external_search_glue_{index}(output: *mut fre_aot_static_runtime::RawStaticSearchSpanAdoptionOutputV1) -> u32;",
            built.glue_symbol
        )
        .unwrap();
        let candidate_compile_identity = hex(&built.compile_identity);
        let compile_receipt_sha256 = hex(&sha256(&built.compile_receipt));
        let implementation_object_sha256 = hex(&sha256(&built.implementation));
        let glue_object_sha256 = hex(&sha256(&built.glue));
        require(
            compile_identities.insert(candidate_compile_identity.clone())
                && compile_receipts.insert(compile_receipt_sha256.clone())
                && implementation_objects.insert(implementation_object_sha256.clone())
                && glue_objects.insert(glue_object_sha256.clone())
                && glue_symbols.insert(built.glue_symbol.clone()),
            "candidate compile, object, or symbol identity is not injective",
        );
        built_candidates.push(StagedCandidate {
            candidate: candidate.clone(),
            compile_identity: candidate_compile_identity,
            compile_receipt_sha256,
            compile_receipt_basename,
            implementation_object_sha256,
            glue_object_sha256,
            implementation_object_basename,
            glue_object_basename,
            implementation_symbols: built.implementation_symbols,
            glue_symbol: built.glue_symbol,
        });
    }
    let manifest_identity = emitted_manifest_identity
        .clone()
        .expect("one emitted manifest identity");
    generated.push_str("}\n");
    writeln!(
        generated,
        "pub(crate) const COMPILER_IDENTITY: &str = {compiler_identity:?};"
    )
    .unwrap();
    writeln!(
        generated,
        "pub(crate) const PLATFORM_MANIFEST_IDENTITY: &str = {manifest_identity:?};"
    )
    .unwrap();
    writeln!(
        generated,
        "pub(crate) const SOURCE_ARCHIVE_SHA256: &str = {source_archive_sha256:?};"
    )
    .unwrap();
    writeln!(
        generated,
        "pub(crate) const PRIVATE_FAMILY_SOURCE_SHA256: &str = {private_family_source_sha256:?};"
    )
    .unwrap();
    let mut built_refusals = Vec::new();
    for (index, candidate) in literal_dispositions.refusals.iter().enumerate() {
        let (compile_receipt, refusal_manifest_identity) = if target_os == "macos" {
            refuse_macos(candidate, backend_tag, index)
        } else {
            refuse_linux(candidate, backend_tag, index)
        };
        require(
            hex(&refusal_manifest_identity) == manifest_identity,
            "refusal and object compiler manifests differ",
        );
        let compile_receipt_basename =
            format!("external-search-refusal-{index}-compile-receipt.bin");
        let compile_receipt_sha256 = hex(&sha256(&compile_receipt));
        require(
            compile_receipts.insert(compile_receipt_sha256.clone()),
            "refusal compiler receipt identity is not injective",
        );
        fs::write(output.join(&compile_receipt_basename), compile_receipt)
            .expect("structural-refusal compiler receipt");
        built_refusals.push(StagedRefusal {
            candidate: candidate.clone(),
            compile_receipt_sha256,
            compile_receipt_basename,
        });
    }
    generated.push_str(
        "#[allow(unsafe_code, unsafe_op_in_unsafe_fn)]\npub(crate) unsafe fn invoke(index: usize, output: *mut fre_aot_static_runtime::RawStaticSearchSpanAdoptionOutputV1) -> u32 {\n    match index {\n",
    );
    for index in 0..candidate_manifest.candidates.len() {
        writeln!(
            generated,
            "        {index} => unsafe {{ external_search_glue_{index}(output) }},"
        )
        .unwrap();
    }
    generated.push_str(
        "        _ => fre_aot_static_runtime::STATIC_SEARCH_SPAN_ADOPT_STATUS_UNQUALIFIED_SELECTOR_V1,\n    }\n}\n",
    );
    generated.push_str("pub(crate) static CANDIDATES: &[CandidateIdentity] = &[\n");
    for built in &built_candidates {
        writeln!(
            generated,
            "    CandidateIdentity {{ semantic_candidate_sha256: {:?}, literal_hex: {:?}, implementation_sha256: {:?}, glue_sha256: {:?} }},",
            built.candidate.semantic_candidate_sha256,
            built.candidate.literal_hex,
            built.implementation_object_sha256,
            built.glue_object_sha256,
        )
        .unwrap();
    }
    generated.push_str("];\n");
    fs::write(output.join("generated.rs"), generated).expect("generated runner bindings");
    fs::write(output.join("identity.json"), &identity_bytes).expect("copied identity");

    let receipt = json!({
        "schema": "fre.aot.search-tag30-ripgrep-application-runner-build-receipt.v1",
        "identity_sha256": hex(&identity_sha256),
        "runner_revision": revision,
        "runner_source_sha256": hex(&source_identity),
        "source_archive_sha256": source_archive_sha256,
        "private_family_source_sha256": private_family_source_sha256,
        "target_os": target_os,
        "target_arch": target_arch,
        "backend_name": backend_name,
        "backend_tag": backend_tag,
        "backend_version": "SEARCH_V17",
        "candidate_policy": 15,
        "llvm": false,
        "compiler_identity": compiler_identity,
        "manifest_identity": manifest_identity,
        "family_selector": family_selector,
        "minimum_window_bytes": minimum_window_bytes,
        "portable_prefix_candidate_starts": portable_prefix_candidate_starts,
        "plan_identity": plan_identity,
        "analyzer_identity": analyzer_identity,
        "evidence_identity": evidence_identity,
        "private_family_authorization_identity": private_authorization_identity,
        "application_contract_identity": application_contract_identity,
        "application_qualification_authority": timing_permitted,
        "production_authority": false,
        "rebar_accepted_as_input": false,
        "timing_permitted": timing_permitted,
        "object_candidate_manifest_schema": candidate_manifest.schema,
        "object_candidate_manifest_sha256": candidate_manifest.sha256,
        "object_candidate_manifest_payload_sha256": candidate_manifest.payload_sha256,
        "object_candidate_count": candidate_manifest.candidates.len(),
        "literal_dispositions_sha256": literal_dispositions.sha256,
        "literal_dispositions_payload_sha256": literal_dispositions.payload_sha256,
        "literal_disposition_count": literal_dispositions.literal_count,
        "fixture_manifest_schema": fixture_manifest_schema,
        "fixture_manifest_sha256": fixture_manifest_sha256,
        "canonical_byte_escaped_sources": candidate_manifest.canonical_byte_escaped_sources,
        "candidates": built_candidates.iter().enumerate().map(|(ordinal, built)| json!({
            "ordinal": ordinal,
            "semantic_candidate_sha256": built.candidate.semantic_candidate_sha256,
            "literal_sha256": built.candidate.literal_sha256,
            "literal_hex": built.candidate.literal_hex,
            "compile_identity": built.compile_identity,
            "compile_receipt_sha256": built.compile_receipt_sha256,
            "compile_receipt_basename": built.compile_receipt_basename,
            "implementation_object_sha256": built.implementation_object_sha256,
            "glue_object_sha256": built.glue_object_sha256,
            "implementation_object_basename": built.implementation_object_basename,
            "glue_object_basename": built.glue_object_basename,
            "implementation_symbols": {
                "entry": built.implementation_symbols[0],
                "payload": built.implementation_symbols[1],
                "metadata": built.implementation_symbols[2],
            },
            "glue_symbol": built.glue_symbol,
        })).collect::<Vec<_>>(),
        "refusals": built_refusals.iter().enumerate().map(|(ordinal, built)| json!({
            "ordinal": ordinal,
            "semantic_candidate_sha256": built.candidate.semantic_candidate_sha256,
            "literal_sha256": built.candidate.literal_sha256,
            "literal_hex": built.candidate.literal_hex,
            "disposition": "structural-refusal",
            "compile_receipt_sha256": built.compile_receipt_sha256,
            "compile_receipt_basename": built.compile_receipt_basename,
        })).collect::<Vec<_>>(),
    });
    fs::write(
        output.join("build-receipt.json"),
        serde_json::to_vec_pretty(&receipt).expect("build receipt JSON"),
    )
    .expect("build receipt");

    if target_os == "macos" {
        println!("cargo:rustc-link-arg-bin={BINARY}=-Wl,-segprot,__TEXT,rx,rx");
        println!("cargo:rustc-link-arg-bin={BINARY}=-Wl,-segprot,__FRE_CONST,r,r");
        println!("cargo:rustc-link-arg-bin={BINARY}=-Wl,-reproducible");
        println!(
            "cargo:rustc-link-arg-bin={BINARY}=-Wl,-map,{}",
            output.join("linked-image.map").display()
        );
    } else {
        println!("cargo:rustc-link-arg-bin={BINARY}=-Wl,-z,separate-code");
        println!("cargo:rustc-link-arg-bin={BINARY}=-Wl,-z,noexecstack");
        println!("cargo:rustc-link-arg-bin={BINARY}=-Wl,--build-id=none");
        println!(
            "cargo:rustc-link-arg-bin={BINARY}=-Wl,-Map,{}",
            output.join("linked-image.map").display()
        );
    }
}

fn build_macos(candidate: &Candidate, backend_tag: u16, selector: u16) -> BuiltCandidate {
    let manifest = MacosAarch64ExactSearchManifestV1::<Span>::candidate_backend_tag(
        SearchCompilePolicyV1::high_fuel(),
        backend_tag,
    )
    .expect("supported macOS candidate backend tag");
    let manifest_identity = *manifest.identity().as_bytes();
    let compiled = plan_and_compile_macos_aarch64_exact_search_v1(
        manifest,
        exact_source(&candidate.source),
        RustProfile::default(),
    )
    .expect("macOS external Search object");
    require(
        compiled.receipt().literal_bytes()
            == u32::try_from(candidate.literal.len()).expect("bounded literal width"),
        "macOS compiled literal width differs from object-candidate manifest",
    );
    let expectation =
        build_static_search_span_expectation_v1(&compiled).expect("macOS static expectation");
    let glue = publish_search_span_family_qualification_final_image_glue_v1(
        &compiled,
        &expectation,
        selector,
        SearchSpanFinalImageGlueLimitsV1::default(),
    )
    .expect("macOS private-family glue");
    let symbols = compiled.object().exported_symbols();
    let compile_identity = *compiled.receipt().compile_identity().as_bytes();
    let glue_symbol = format!("{GLUE_SYMBOL_PREFIX}{}", hex(&compile_identity));
    BuiltCandidate {
        implementation: compiled.object().as_bytes().to_vec(),
        glue: glue.object().as_bytes().to_vec(),
        compile_receipt: compiled
            .receipt()
            .canonical_bytes()
            .expect("canonical macOS compiler receipt")
            .to_vec(),
        compile_identity,
        manifest_identity,
        implementation_symbols: [
            symbols.entry().as_str().to_owned(),
            symbols.payload().as_str().to_owned(),
            symbols.metadata().as_str().to_owned(),
        ],
        glue_symbol,
    }
}

fn build_linux(candidate: &Candidate, backend_tag: u16, selector: u16) -> BuiltCandidate {
    let manifest = LinuxAarch64ExactSearchManifestV1::<Span>::candidate_backend_tag(
        LinuxAarch64SearchCompilePolicyV1::high_fuel(),
        backend_tag,
    )
    .expect("supported Linux candidate backend tag");
    let manifest_identity = *manifest.identity().as_bytes();
    let compiled = plan_and_compile_linux_aarch64_exact_search_v1(
        manifest,
        exact_source(&candidate.source),
        RustProfile::default(),
    )
    .expect("Linux external Search object");
    require(
        compiled.receipt().literal_bytes()
            == u32::try_from(candidate.literal.len()).expect("bounded literal width"),
        "Linux compiled literal width differs from object-candidate manifest",
    );
    let expectation =
        build_linux_static_search_span_expectation_v1(&compiled).expect("Linux static expectation");
    let glue = publish_linux_search_span_family_qualification_final_image_glue_v1(
        &compiled,
        &expectation,
        selector,
        LinuxSearchSpanFinalImageGlueLimitsV1::default(),
    )
    .expect("Linux private-family glue");
    let symbols = compiled.object().exported_symbols();
    let glue_symbols = glue
        .object()
        .exported_symbols()
        .expect("canonical Linux final-image symbols");
    let compile_identity = *compiled.receipt().compile_identity().as_bytes();
    require(
        glue_symbols.entry().as_str() == symbols.entry().as_str()
            && glue_symbols.payload().as_str() == symbols.payload().as_str()
            && glue_symbols.metadata().as_str() == symbols.metadata().as_str(),
        "Linux glue implementation namespace differs from compiler object",
    );
    BuiltCandidate {
        implementation: compiled.object().as_bytes().to_vec(),
        glue: glue.object().as_bytes().to_vec(),
        compile_receipt: compiled
            .receipt()
            .canonical_receipt_bytes()
            .expect("canonical Linux compiler receipt")
            .to_vec(),
        compile_identity,
        manifest_identity,
        implementation_symbols: [
            symbols.entry().as_str().to_owned(),
            symbols.payload().as_str().to_owned(),
            symbols.metadata().as_str().to_owned(),
        ],
        glue_symbol: glue_symbols.glue().as_str().to_owned(),
    }
}

fn refusal_receipt(
    candidate: &Candidate,
    target_os: &str,
    manifest_identity: &[u8; 32],
    ordinal: usize,
) -> Vec<u8> {
    let payload = json!({
        "target_os": target_os,
        "target_arch": "aarch64",
        "backend_name": "AsimdV17",
        "backend_tag": 30,
        "backend_version": "SEARCH_V17",
        "candidate_policy": 15,
        "llvm": false,
        "manifest_identity": hex(manifest_identity),
        "ordinal": ordinal,
        "semantic_candidate_sha256": candidate.semantic_candidate_sha256,
        "literal_sha256": candidate.literal_sha256,
        "literal_hex": candidate.literal_hex,
        "literal_bytes": candidate.literal.len(),
        "source_construction": "canonical-byte-escaped-exact",
        "source_sha256": hex(&sha256(&candidate.source)),
        "compiler_entrypoint": if target_os == "macos" {
            "plan_and_compile_macos_aarch64_exact_search_v1"
        } else {
            "plan_and_compile_linux_aarch64_exact_search_v1"
        },
        "compiler_outcome": "error",
        "compiler_error": "Native(Unsupported { reason: KernelShape })",
        "disposition": "structural-refusal",
    });
    let payload_bytes = serde_json::to_vec(&payload).expect("canonical refusal payload JSON");
    let envelope = json!({
        "schema": REFUSAL_RECEIPT_SCHEMA,
        "payload_sha256": hex(&sha256(&payload_bytes)),
        "payload": payload,
    });
    let mut encoded = serde_json::to_vec(&envelope).expect("canonical refusal receipt JSON");
    encoded.push(b'\n');
    encoded
}

fn refuse_macos(candidate: &Candidate, backend_tag: u16, ordinal: usize) -> (Vec<u8>, [u8; 32]) {
    let manifest = MacosAarch64ExactSearchManifestV1::<Span>::candidate_backend_tag(
        SearchCompilePolicyV1::high_fuel(),
        backend_tag,
    )
    .expect("supported macOS candidate backend tag");
    let manifest_identity = *manifest.identity().as_bytes();
    match plan_and_compile_macos_aarch64_exact_search_v1(
        manifest,
        exact_source(&candidate.source),
        RustProfile::default(),
    ) {
        Err(SearchCompileErrorV1::Native(EmitError::Unsupported {
            reason: UnsupportedReason::KernelShape,
        })) => {}
        Err(error) => {
            panic!("macOS structural-refusal compile returned a different error: {error:?}")
        }
        Ok(_) => panic!("macOS structural-refusal compile emitted an object"),
    }
    (
        refusal_receipt(candidate, "macos", &manifest_identity, ordinal),
        manifest_identity,
    )
}

fn refuse_linux(candidate: &Candidate, backend_tag: u16, ordinal: usize) -> (Vec<u8>, [u8; 32]) {
    let manifest = LinuxAarch64ExactSearchManifestV1::<Span>::candidate_backend_tag(
        LinuxAarch64SearchCompilePolicyV1::high_fuel(),
        backend_tag,
    )
    .expect("supported Linux candidate backend tag");
    let manifest_identity = *manifest.identity().as_bytes();
    match plan_and_compile_linux_aarch64_exact_search_v1(
        manifest,
        exact_source(&candidate.source),
        RustProfile::default(),
    ) {
        Err(LinuxSearchCompileErrorV1::Native(EmitError::Unsupported {
            reason: UnsupportedReason::KernelShape,
        })) => {}
        Err(error) => {
            panic!("Linux structural-refusal compile returned a different error: {error:?}")
        }
        Ok(_) => panic!("Linux structural-refusal compile emitted an object"),
    }
    (
        refusal_receipt(candidate, "linux", &manifest_identity, ordinal),
        manifest_identity,
    )
}

fn load_candidate_manifest(
    path: &Path,
    identity: &Value,
    minimum_literal_bytes: u32,
    maximum_literal_bytes: u32,
) -> Result<CandidateManifest, String> {
    let bytes = regular_file(path, MAXIMUM_CANDIDATE_MANIFEST_BYTES)?;
    let manifest_sha256 = hex(&sha256(&bytes));
    let root: Value = serde_json::from_slice(&bytes)
        .map_err(|error| format!("object-candidate manifest JSON: {error}"))?;
    let schema = root
        .get("schema")
        .and_then(Value::as_str)
        .ok_or_else(|| "object-candidate manifest lacks a string schema".to_owned())?;
    let canonical_byte_escaped_sources = true;
    if path_str(identity, &["object_candidates", "source_construction"])
        != CANONICAL_SOURCE_CONSTRUCTION
    {
        return Err("object-candidate source construction differs".to_owned());
    }
    let expected_schema = path_str(identity, &["object_candidates", "manifest_schema"]);
    let expected_sha256 = path_str(identity, &["object_candidates", "manifest_sha256"]);
    let expected_count = path_usize(identity, &["object_candidates", "candidate_count"]);
    if schema != expected_schema {
        return Err("object-candidate manifest schema differs from identity".to_owned());
    }
    if manifest_sha256 != expected_sha256 {
        return Err("object-candidate manifest SHA-256 differs from identity".to_owned());
    }
    let payload_sha256 = root
        .get("payload_sha256")
        .and_then(Value::as_str)
        .ok_or_else(|| "object-candidate payload identity is absent".to_owned())?;
    let payload = root
        .get("payload")
        .and_then(Value::as_object)
        .ok_or_else(|| "object-candidate manifest lacks an object payload".to_owned())?;
    let payload_bytes = serde_json::to_vec(payload)
        .map_err(|error| format!("object-candidate payload JSON: {error}"))?;
    if !is_hex(payload_sha256, 64) || payload_sha256 != hex(&sha256(&payload_bytes)) {
        return Err("object-candidate payload identity is malformed".to_owned());
    }
    if payload
        .get("timing_permitted")
        .and_then(Value::as_bool)
        .is_some_and(|permitted| permitted)
        || payload
            .get("timing_feedback_permitted")
            .and_then(Value::as_bool)
            .is_some_and(|permitted| permitted)
    {
        return Err("object-candidate source manifest improperly grants timing".to_owned());
    }
    let declared_count = payload
        .get("candidate_count")
        .and_then(Value::as_u64)
        .and_then(|value| usize::try_from(value).ok())
        .ok_or_else(|| "object-candidate manifest count is invalid".to_owned())?;
    let raw_candidates = payload
        .get("candidates")
        .and_then(Value::as_array)
        .ok_or_else(|| "object-candidate manifest lacks a candidate array".to_owned())?;
    if expected_count == 0
        || expected_count > MAXIMUM_CANDIDATES
        || declared_count != expected_count
        || raw_candidates.len() != expected_count
    {
        return Err("object-candidate manifest cardinality differs from identity".to_owned());
    }

    let mut semantic_identities = BTreeSet::new();
    let mut literal_identities = BTreeSet::new();
    let mut candidates = Vec::new();
    candidates
        .try_reserve_exact(expected_count)
        .map_err(|_| "object-candidate allocation failed".to_owned())?;
    for raw in raw_candidates {
        candidates.push(parse_candidate(
            raw,
            minimum_literal_bytes,
            maximum_literal_bytes,
            canonical_byte_escaped_sources,
            &mut semantic_identities,
            &mut literal_identities,
        )?);
    }
    Ok(CandidateManifest {
        schema: schema.to_owned(),
        sha256: manifest_sha256,
        payload_sha256: payload_sha256.to_owned(),
        canonical_byte_escaped_sources,
        candidates,
    })
}

fn candidate_signature_is_cyclic_phase_unique(literal: &[u8], selected: &[usize]) -> bool {
    if !(6..=32).contains(&literal.len())
        || selected.len() != 5
        || selected.iter().any(|&offset| offset >= literal.len())
        || selected
            .iter()
            .enumerate()
            .any(|(index, offset)| selected[..index].contains(offset))
    {
        return false;
    }
    (1..literal.len()).all(|shift| {
        selected.iter().any(|&offset| {
            let shifted = offset
                .checked_add(shift)
                .expect("bounded tag30 cyclic offset")
                .checked_rem(literal.len())
                .expect("nonempty tag30 literal");
            literal[offset] != literal[shifted]
        })
    })
}

#[allow(
    clippy::too_many_lines,
    reason = "one transaction authenticates the complete disposition envelope, structural classifier, and exact object/refusal partition"
)]
fn load_literal_dispositions(
    path: &Path,
    candidates: &CandidateManifest,
    minimum_literal_bytes: u32,
    maximum_literal_bytes: u32,
) -> Result<LiteralDispositions, String> {
    let bytes = regular_file(path, MAXIMUM_LITERAL_DISPOSITIONS_BYTES)?;
    let file_sha256 = hex(&sha256(&bytes));
    let root: Value = serde_json::from_slice(&bytes)
        .map_err(|error| format!("literal-dispositions JSON: {error}"))?;
    let object = root
        .as_object()
        .ok_or_else(|| "literal-dispositions root is not an object".to_owned())?;
    let root_keys = object.keys().map(String::as_str).collect::<BTreeSet<_>>();
    if root_keys != BTreeSet::from(["schema", "payload_sha256", "payload"])
        || root.get("schema").and_then(Value::as_str) != Some(LITERAL_DISPOSITIONS_SCHEMA)
    {
        return Err("literal-dispositions envelope changed".to_owned());
    }
    let payload_sha256 = root
        .get("payload_sha256")
        .and_then(Value::as_str)
        .ok_or_else(|| "literal-dispositions payload identity is absent".to_owned())?;
    let payload = root
        .get("payload")
        .and_then(Value::as_object)
        .ok_or_else(|| "literal-dispositions payload is absent".to_owned())?;
    let payload_keys = payload.keys().map(String::as_str).collect::<BTreeSet<_>>();
    if payload_keys
        != BTreeSet::from([
            "freeze_sha256",
            "freeze_payload_sha256",
            "inventory_sha256",
            "inventory_payload_sha256",
            "selector_contract_sha256",
            "selector_implementation_sha256",
            "fixture_manifest_sha256",
            "fixture_manifest_payload_sha256",
            "upstream_commit",
            "upstream_tree",
            "timing_permitted",
            "timing_feedback_permitted",
            "external_inputs",
            "benchmark_results",
            "rebar_inputs",
            "network",
            "production_authority",
            "application_qualification_authority",
            "campaign_plan_identity",
            "private_family_authorization_identity",
            "literal_count",
            "eligible_literal_count",
            "ineligible_literal_count",
            "dispositions",
        ])
        || payload.get("timing_permitted").and_then(Value::as_bool) != Some(false)
        || payload
            .get("timing_feedback_permitted")
            .and_then(Value::as_bool)
            != Some(false)
        || payload.get("network").and_then(Value::as_bool) != Some(false)
        || payload.get("production_authority").and_then(Value::as_bool) != Some(false)
        || payload
            .get("application_qualification_authority")
            .and_then(Value::as_bool)
            != Some(false)
        || !payload
            .get("campaign_plan_identity")
            .is_some_and(Value::is_null)
        || !payload
            .get("private_family_authorization_identity")
            .is_some_and(Value::is_null)
        || ["external_inputs", "benchmark_results", "rebar_inputs"]
            .iter()
            .any(|field| {
                payload
                    .get(*field)
                    .and_then(Value::as_array)
                    .is_none_or(|values| !values.is_empty())
            })
    {
        return Err("literal-dispositions authority changed".to_owned());
    }
    let canonical_payload = serde_json::to_vec(payload)
        .map_err(|error| format!("literal-dispositions payload JSON: {error}"))?;
    if !is_hex(payload_sha256, 64) || payload_sha256 != hex(&sha256(&canonical_payload)) {
        return Err("literal-dispositions payload identity differs".to_owned());
    }
    let dispositions = payload
        .get("dispositions")
        .and_then(Value::as_array)
        .ok_or_else(|| "literal-dispositions rows are absent".to_owned())?;
    let literal_count = payload
        .get("literal_count")
        .and_then(Value::as_u64)
        .and_then(|value| usize::try_from(value).ok())
        .ok_or_else(|| "literal-dispositions count is invalid".to_owned())?;
    let eligible_count = payload
        .get("eligible_literal_count")
        .and_then(Value::as_u64)
        .and_then(|value| usize::try_from(value).ok())
        .ok_or_else(|| "eligible literal count is invalid".to_owned())?;
    let ineligible_count = payload
        .get("ineligible_literal_count")
        .and_then(Value::as_u64)
        .and_then(|value| usize::try_from(value).ok())
        .ok_or_else(|| "ineligible literal count is invalid".to_owned())?;
    if literal_count == 0
        || literal_count > MAXIMUM_LITERAL_DISPOSITIONS
        || dispositions.len() != literal_count
        || eligible_count != candidates.candidates.len()
        || eligible_count.checked_add(ineligible_count) != Some(literal_count)
    {
        return Err("literal-dispositions cardinality changed".to_owned());
    }
    let mut semantic_identities = BTreeSet::new();
    let mut literal_identities = BTreeSet::new();
    let mut eligible = Vec::new();
    let mut refusals = Vec::new();
    for (ordinal, raw) in dispositions.iter().enumerate() {
        let row = raw
            .as_object()
            .ok_or_else(|| format!("literal disposition {ordinal} is not an object"))?;
        let row_keys = row.keys().map(String::as_str).collect::<BTreeSet<_>>();
        if row_keys
            != BTreeSet::from([
                "semantic_candidate_sha256",
                "literal_hex",
                "literal_sha256",
                "literal_bytes",
                "selected_offsets",
                "selector_eligible",
                "expected_compiler_disposition",
            ])
        {
            return Err(format!("literal disposition {ordinal} fields changed"));
        }
        let candidate = parse_candidate(
            raw,
            1,
            maximum_literal_bytes,
            true,
            &mut semantic_identities,
            &mut literal_identities,
        )?;
        let selected_values = row
            .get("selected_offsets")
            .and_then(Value::as_array)
            .ok_or_else(|| format!("literal disposition {ordinal} offsets changed"))?;
        let selected = selected_values
            .iter()
            .map(|value| {
                value
                    .as_u64()
                    .and_then(|offset| usize::try_from(offset).ok())
                    .ok_or_else(|| format!("literal disposition {ordinal} offset changed"))
            })
            .collect::<Result<Vec<_>, _>>()?;
        if selected.is_empty() || selected.len() > 5 {
            return Err(format!(
                "literal disposition {ordinal} offset count changed"
            ));
        }
        let actual_eligible =
            candidate_signature_is_cyclic_phase_unique(&candidate.literal, &selected);
        let declared_eligible = row
            .get("selector_eligible")
            .and_then(Value::as_bool)
            .ok_or_else(|| format!("literal disposition {ordinal} eligibility changed"))?;
        let disposition = row
            .get("expected_compiler_disposition")
            .and_then(Value::as_str)
            .ok_or_else(|| format!("literal disposition {ordinal} compiler outcome changed"))?;
        if declared_eligible != actual_eligible
            || disposition
                != if actual_eligible {
                    "tag30-object"
                } else {
                    "structural-refusal"
                }
            || (actual_eligible
                && (u32::try_from(candidate.literal.len()).ok() < Some(minimum_literal_bytes)))
        {
            return Err(format!(
                "literal disposition {ordinal} structural classification changed"
            ));
        }
        if actual_eligible {
            eligible.push(candidate);
        } else {
            refusals.push(candidate);
        }
    }
    if eligible != candidates.candidates
        || eligible.len() != eligible_count
        || refusals.len() != ineligible_count
    {
        return Err("literal dispositions do not biject to object candidates".to_owned());
    }
    Ok(LiteralDispositions {
        sha256: file_sha256,
        payload_sha256: payload_sha256.to_owned(),
        literal_count,
        refusals,
    })
}

fn parse_candidate(
    raw: &Value,
    minimum_literal_bytes: u32,
    maximum_literal_bytes: u32,
    canonical_byte_escaped_sources: bool,
    semantic_identities: &mut BTreeSet<String>,
    literal_identities: &mut BTreeSet<Vec<u8>>,
) -> Result<Candidate, String> {
    let candidate = raw
        .as_object()
        .ok_or_else(|| "object candidate is not an object".to_owned())?;
    let semantic_candidate_sha256 = candidate
        .get("semantic_candidate_sha256")
        .and_then(Value::as_str)
        .ok_or_else(|| "object candidate lacks a semantic identity".to_owned())?;
    if !is_hex(semantic_candidate_sha256, 64)
        || !semantic_identities.insert(semantic_candidate_sha256.to_owned())
    {
        return Err("object candidate semantic identity is malformed or duplicated".to_owned());
    }
    let literal_hex = candidate
        .get("literal_hex")
        .and_then(Value::as_str)
        .ok_or_else(|| "object candidate lacks literal hex".to_owned())?;
    let literal = decode_hex(literal_hex)?;
    let width = u32::try_from(literal.len())
        .map_err(|_| "object candidate literal width overflows".to_owned())?;
    if width < minimum_literal_bytes
        || width > maximum_literal_bytes
        || !literal_identities.insert(literal.clone())
    {
        return Err(
            "object candidate literal is duplicated or outside the routing envelope".to_owned(),
        );
    }
    if candidate
        .get("literal_bytes")
        .and_then(Value::as_u64)
        .is_some_and(|declared| declared != u64::from(width))
    {
        return Err("object candidate literal width differs".to_owned());
    }
    let literal_sha256 = hex(&sha256(&literal));
    if candidate.get("literal_sha256").and_then(Value::as_str) != Some(literal_sha256.as_str()) {
        return Err("object candidate literal identity differs".to_owned());
    }
    // The application semantic identity additionally binds the authenticated
    // ripgrep source location and cannot be reconstructed from this compact
    // object manifest alone. Its exact value is instead frozen by the
    // byte-exact manifest identity and checked bijectively against the
    // independently derived disposition manifest.
    let source = if canonical_byte_escaped_sources {
        canonical_exact_source(&literal).into_bytes()
    } else {
        literal.clone()
    };
    let source_text = String::from_utf8(source.clone())
        .map_err(|_| "object candidate source is not UTF-8".to_owned())?;
    let mut builder = PortableBuilder::new(source_text).profile(RustProfile::default());
    if !canonical_byte_escaped_sources {
        builder = builder.unicode(true);
    }
    let portable = builder
        .build()
        .map_err(|error| format!("object candidate source does not compile: {error}"))?;
    let exact = portable
        .exact_literal_search_aot_candidate()
        .ok_or_else(|| "object candidate source is not one exact literal".to_owned())?;
    if exact.literal() != literal {
        return Err("object candidate source and literal differ".to_owned());
    }
    Ok(Candidate {
        semantic_candidate_sha256: semantic_candidate_sha256.to_owned(),
        source,
        literal,
        literal_hex: literal_hex.to_owned(),
        literal_sha256,
    })
}

fn canonical_exact_source(literal: &[u8]) -> String {
    let mut source = String::with_capacity(
        literal
            .len()
            .checked_mul(4)
            .and_then(|bytes| bytes.checked_add(6))
            .expect("bounded object candidate source"),
    );
    source.push_str("(?-u:");
    for byte in literal {
        write!(source, "\\x{byte:02x}").expect("String formatting");
    }
    source.push(')');
    source
}

fn decode_hex(value: &str) -> Result<Vec<u8>, String> {
    if value.is_empty()
        || !value.len().is_multiple_of(2)
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    {
        return Err("object candidate literal is not canonical lowercase hex".to_owned());
    }
    let mut output = Vec::new();
    output
        .try_reserve_exact(value.len() / 2)
        .map_err(|_| "object candidate literal allocation failed".to_owned())?;
    for pair in value.as_bytes().chunks_exact(2) {
        let text = std::str::from_utf8(pair)
            .map_err(|_| "object candidate literal hex is not UTF-8".to_owned())?;
        output.push(
            u8::from_str_radix(text, 16)
                .map_err(|_| "object candidate literal hex is invalid".to_owned())?,
        );
    }
    Ok(output)
}

fn exact_source(bytes: &[u8]) -> Vec<u8> {
    let mut source = Vec::new();
    source
        .try_reserve_exact(bytes.len())
        .expect("exact source allocation");
    assert_eq!(source.capacity(), bytes.len());
    source.extend_from_slice(bytes);
    source
}

fn write_scaffold(output: &Path) -> Result<(), std::io::Error> {
    let mut generated = String::new();
    generated.push_str(
        "#[derive(Clone, Copy, Debug)]\npub(crate) struct CandidateIdentity { pub(crate) semantic_candidate_sha256: &'static str, pub(crate) literal_hex: &'static str, pub(crate) implementation_sha256: &'static str, pub(crate) glue_sha256: &'static str }\n",
    );
    generated.push_str(
        "pub(crate) const LINKED: bool = false;\npub(crate) const TIMING_PERMITTED: bool = false;\npub(crate) const BACKEND_TAG: u16 = 0;\npub(crate) const BACKEND_NAME: &str = \"unresolved\";\npub(crate) const FAMILY_SELECTOR: u16 = 0;\npub(crate) const MINIMUM_WINDOW_BYTES: usize = 1;\npub(crate) const PORTABLE_PREFIX_CANDIDATE_STARTS: usize = 1;\npub(crate) const PLAN_IDENTITY: &str = \"unresolved\";\npub(crate) const ANALYZER_IDENTITY: &str = \"unresolved\";\npub(crate) const EVIDENCE_IDENTITY: &str = \"unresolved\";\npub(crate) const PRIVATE_AUTHORIZATION_IDENTITY: &str = \"unresolved\";\npub(crate) const APPLICATION_CONTRACT_IDENTITY: &str = \"unresolved\";\npub(crate) const IDENTITY_SHA256: &str = \"unresolved\";\npub(crate) const RUNNER_SOURCE_SHA256: &str = \"unresolved\";\npub(crate) const SOURCE_ARCHIVE_SHA256: &str = \"unresolved\";\npub(crate) const PRIVATE_FAMILY_SOURCE_SHA256: &str = \"unresolved\";\npub(crate) const COMPILER_IDENTITY: &str = \"unresolved\";\npub(crate) const PLATFORM_MANIFEST_IDENTITY: &str = \"unresolved\";\npub(crate) const OBJECT_CANDIDATE_MANIFEST_SCHEMA: &str = \"unresolved\";\npub(crate) const OBJECT_CANDIDATE_MANIFEST_SHA256: &str = \"unresolved\";\npub(crate) const LITERAL_DISPOSITIONS_SHA256: &str = \"unresolved\";\npub(crate) const FIXTURE_MANIFEST_SCHEMA: &str = \"unresolved\";\npub(crate) const FIXTURE_MANIFEST_SHA256: &str = \"unresolved\";\npub(crate) const CANONICAL_BYTE_ESCAPED_SOURCES: bool = false;\npub(crate) static CANDIDATES: &[CandidateIdentity] = &[];\n",
    );
    generated.push_str(
        "#[allow(unsafe_code, unused_variables, reason = \"selector-neutral scaffold has no linked glue to invoke\")]\npub(crate) unsafe fn invoke(index: usize, output: *mut fre_aot_static_runtime::RawStaticSearchSpanAdoptionOutputV1) -> u32 { fre_aot_static_runtime::STATIC_SEARCH_SPAN_ADOPT_STATUS_NO_QUALIFIED_ROW_V1 }\n",
    );
    fs::write(output.join("generated.rs"), generated)
}

fn source_manifest() -> Result<Vec<String>, String> {
    let text = fs::read_to_string("runner-source-files.txt")
        .map_err(|error| format!("read source manifest: {error}"))?;
    if text.is_empty() || !text.ends_with('\n') {
        return Err("source manifest must be nonempty and newline terminated".to_owned());
    }
    let names = text.lines().map(str::to_owned).collect::<Vec<_>>();
    let mut canonical = names.clone();
    canonical.sort();
    canonical.dedup();
    if names != canonical
        || names.iter().any(|name| {
            name.is_empty()
                || name.starts_with('/')
                || name.contains('\\')
                || name.split('/').any(|part| matches!(part, "" | "." | ".."))
        })
    {
        return Err("source manifest is not canonical".to_owned());
    }
    Ok(names)
}

fn runner_source_identity() -> Result<[u8; 32], String> {
    let mut hasher = Sha256::new();
    hasher.update(SOURCE_DOMAIN);
    for name in source_manifest()? {
        let bytes = regular_file(Path::new(&name), 1 << 20)?;
        hasher.update(name.as_bytes());
        hasher.update([0]);
        hasher.update(
            u64::try_from(bytes.len())
                .map_err(|_| "source length overflow")?
                .to_le_bytes(),
        );
        hasher.update(bytes);
    }
    Ok(hasher.finalize().into())
}

fn regular_file(path: &Path, maximum: u64) -> Result<Vec<u8>, String> {
    let metadata = fs::symlink_metadata(path)
        .map_err(|error| format!("metadata {}: {error}", path.display()))?;
    if !metadata.is_file() || metadata.file_type().is_symlink() || metadata.len() > maximum {
        return Err(format!("not one bounded regular file: {}", path.display()));
    }
    fs::read(path).map_err(|error| format!("read {}: {error}", path.display()))
}

fn path_str<'a>(root: &'a Value, path: &[&str]) -> &'a str {
    let mut value = root;
    for component in path {
        value = value
            .get(component)
            .unwrap_or_else(|| panic!("missing {path:?}"));
    }
    value
        .as_str()
        .unwrap_or_else(|| panic!("non-string {path:?}"))
}

fn path_u16(root: &Value, path: &[&str]) -> u16 {
    u16::try_from(path_u64(root, path)).unwrap_or_else(|_| panic!("non-u16 {path:?}"))
}

fn path_u32(root: &Value, path: &[&str]) -> u32 {
    u32::try_from(path_u64(root, path)).unwrap_or_else(|_| panic!("non-u32 {path:?}"))
}

fn path_usize(root: &Value, path: &[&str]) -> usize {
    usize::try_from(path_u64(root, path)).unwrap_or_else(|_| panic!("non-usize {path:?}"))
}

fn path_u64(root: &Value, path: &[&str]) -> u64 {
    let mut value = root;
    for component in path {
        value = value
            .get(component)
            .unwrap_or_else(|| panic!("missing {path:?}"));
    }
    value.as_u64().unwrap_or_else(|| panic!("non-u64 {path:?}"))
}

fn required_path(name: &str) -> PathBuf {
    PathBuf::from(env::var_os(name).unwrap_or_else(|| panic!("missing {name}")))
}

fn require(condition: bool, message: &str) {
    assert!(condition, "{message}");
}

fn is_hex(value: &str, bytes: usize) -> bool {
    value.len() == bytes
        && value
            .bytes()
            .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase())
}

fn sha256(bytes: &[u8]) -> [u8; 32] {
    Sha256::digest(bytes).into()
}

fn compiler_source_identity(revision: &str, archive_sha256: &str) -> String {
    let revision_bytes = decode_hex(revision).expect("canonical source revision hex");
    let archive_bytes = decode_hex(archive_sha256).expect("canonical source archive hex");
    let mut hasher = Sha256::new();
    hasher.update(COMPILER_IDENTITY_DOMAIN);
    hasher.update(revision_bytes);
    hasher.update(archive_bytes);
    hex(&hasher.finalize())
}

fn hex(bytes: &[u8]) -> String {
    let mut output = String::with_capacity(bytes.len().saturating_mul(2));
    for byte in bytes {
        write!(output, "{byte:02x}").expect("String formatting");
    }
    output
}
