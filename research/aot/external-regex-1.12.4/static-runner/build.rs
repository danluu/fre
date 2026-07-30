use std::{
    env,
    fmt::Write as _,
    fs,
    path::{Path, PathBuf},
};

use fre::RustProfile;
use fre_aot_compiler::{
    LinuxAarch64ExactSearchManifestV1, LinuxAarch64SearchCompilePolicyV1,
    LinuxSearchSpanFinalImageGlueLimitsV1, MacosAarch64ExactSearchManifestV1,
    SearchCompilePolicyV1, SearchSpanFinalImageGlueLimitsV1,
    build_linux_static_search_span_expectation_v1, build_static_search_span_expectation_v1,
    plan_and_compile_linux_aarch64_exact_search_v1, plan_and_compile_macos_aarch64_exact_search_v1,
    publish_linux_search_span_family_qualification_final_image_glue_v1,
    publish_search_span_family_qualification_final_image_glue_v1,
};
use fre_kernel_ir::Span;
use serde_json::{Value, json};
use sha2::{Digest, Sha256};

const BINARY: &str = "fre-external-regex-static-runner";
const IDENTITY_ENV: &str = "FRE_EXTERNAL_SEARCH_STATIC_IDENTITY";
const REVISION_ENV: &str = "FRE_EXTERNAL_SEARCH_RUNNER_REVISION";
const UNSEALED_ENV: &str = "FRE_EXTERNAL_SEARCH_ALLOW_UNSEALED_ARTIFACT_BUILD";
const IDENTITY_SCHEMA: &str = "fre.aot.external-regex-1.12.4-static-runner-identity.v1";
const FIXTURE_MANIFEST_SHA256: &str =
    "b979ed327db7e9623bccba1ef775d1957b7323c8b30edb44f40593176f52b44a";
const SOURCE_DOMAIN: &[u8] = b"FRE-EXTERNAL-REGEX-STATIC-RUNNER-SOURCE\0\x01";
const GLUE_SYMBOL_PREFIX: &str = "fre_aot_search_span_glue_v1_";

#[derive(Clone, Copy)]
struct Candidate {
    semantic_candidate_sha256: &'static str,
    source: &'static [u8],
    literal_hex: &'static str,
}

const CANDIDATES: [Candidate; 4] = [
    Candidate {
        semantic_candidate_sha256: "81f5693f70a77293f3e3f0dd59107a406db75773ab9f6ed8614803db5b078ce3",
        source: b"\xe2\x98\x83",
        literal_hex: "e29883",
    },
    Candidate {
        semantic_candidate_sha256: "a2a9256b163317b5c6b4bfefd969adf0c68d671c21bd2cc24cf0dc8b0eadcdca",
        source: b"\xd0\x88\x30\x31",
        literal_hex: "d0883031",
    },
    Candidate {
        semantic_candidate_sha256: "b720c057945898d49a18f82a3096743173bd59629cdda7405c1656cf22791904",
        source: b"\xe2\x80\xa8",
        literal_hex: "e280a8",
    },
    Candidate {
        semantic_candidate_sha256: "fccc7aa283c35d3484418b43513a97b6e36f539bce8b6a2fc00514ff6667876b",
        source: b"abc",
        literal_hex: "616263",
    },
];

struct BuiltCandidate {
    implementation: Vec<u8>,
    glue: Vec<u8>,
    compile_identity: [u8; 32],
    manifest_identity: [u8; 32],
}

#[allow(
    clippy::too_many_lines,
    reason = "the build transaction deliberately keeps identity validation, object emission, and exact linker publication in one auditable sequence"
)]
fn main() {
    println!("cargo:rerun-if-env-changed={IDENTITY_ENV}");
    println!("cargo:rerun-if-env-changed={REVISION_ENV}");
    println!("cargo:rerun-if-env-changed={UNSEALED_ENV}");
    println!("cargo:rerun-if-changed=runner-source-files.txt");
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
    require(
        identity.get("schema").and_then(Value::as_str) == Some(IDENTITY_SCHEMA),
        "static runner identity schema changed",
    );
    require(
        path_str(&identity, &["external_evidence", "fixture_manifest_sha256"])
            == FIXTURE_MANIFEST_SHA256,
        "fixture manifest identity changed",
    );
    require(
        identity.pointer("/emitter/llvm").and_then(Value::as_bool) == Some(false),
        "LLVM is not admissible",
    );
    let backend_tag = path_u16(&identity, &["static_pipeline", "backend_tag"]);
    let backend_name = path_str(&identity, &["static_pipeline", "backend_name"]);
    require(!backend_name.is_empty(), "backend name is empty");
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
    require(
        is_hex(plan_identity, 64) && is_hex(analyzer_identity, 64) && is_hex(evidence_identity, 64),
        "automatic routing qualification identity is malformed",
    );
    require(
        minimum_literal_bytes <= 3 && maximum_literal_bytes >= 4,
        "family width envelope excludes an external candidate",
    );
    require(
        minimum_window_bytes > 0
            && portable_prefix_candidate_starts > 0
            && identity
                .pointer("/auto_routing/full_window_preflight_authoritative")
                .and_then(Value::as_bool)
                == Some(true),
        "automatic routing policy is incomplete",
    );
    let timing_permitted = identity
        .pointer("/state/development_timing_permitted")
        .and_then(Value::as_bool)
        .expect("development timing state");
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
                .is_some_and(Value::is_null),
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

    let target_arch = env::var("CARGO_CFG_TARGET_ARCH").expect("target arch");
    let target_os = env::var("CARGO_CFG_TARGET_OS").expect("target OS");
    require(target_arch == "aarch64", "runner requires AArch64");
    require(
        matches!(target_os.as_str(), "macos" | "linux"),
        "runner requires macOS or Linux",
    );

    let compiler_identity = identity
        .pointer("/static_pipeline/compiler_identity")
        .and_then(Value::as_str);
    if compiler_identity.is_none() {
        require(unsealed, "sealed build lacks compiler identity");
    }
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
    generated.push_str("#[allow(unsafe_code)]\nunsafe extern \"C\" {\n");

    let mut built_candidates = Vec::new();
    let mut emitted_manifest_identity = None;
    for (index, candidate) in CANDIDATES.into_iter().enumerate() {
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
        let implementation_path = output.join(format!("external-search-{index}-implementation.o"));
        let glue_path = output.join(format!("external-search-{index}-family-glue.o"));
        fs::write(&implementation_path, &built.implementation).expect("implementation object");
        fs::write(&glue_path, &built.glue).expect("family glue object");
        println!(
            "cargo:rustc-link-arg-bin={BINARY}={}",
            implementation_path.display()
        );
        println!("cargo:rustc-link-arg-bin={BINARY}={}", glue_path.display());
        writeln!(
            generated,
            "    #[link_name = {:?}] fn external_search_glue_{index}(output: *mut fre_aot_static_runtime::RawStaticSearchSpanAdoptionOutputV1) -> u32;",
            format!("{GLUE_SYMBOL_PREFIX}{}", hex(&built.compile_identity))
        )
        .unwrap();
        built_candidates.push((
            candidate,
            hex(&sha256(&built.implementation)),
            hex(&sha256(&built.glue)),
        ));
    }
    generated.push_str("}\n");
    generated.push_str(
        "#[allow(unsafe_code, unsafe_op_in_unsafe_fn)]\npub(crate) unsafe fn invoke(index: usize, output: *mut fre_aot_static_runtime::RawStaticSearchSpanAdoptionOutputV1) -> u32 {\n    match index {\n",
    );
    for index in 0..CANDIDATES.len() {
        writeln!(
            generated,
            "        {index} => unsafe {{ external_search_glue_{index}(output) }},"
        )
        .unwrap();
    }
    generated.push_str(
        "        _ => fre_aot_static_runtime::STATIC_SEARCH_SPAN_ADOPT_STATUS_UNQUALIFIED_SELECTOR_V1,\n    }\n}\n",
    );
    generated.push_str("pub(crate) const CANDIDATES: [CandidateIdentity; 4] = [\n");
    for (candidate, implementation_sha256, glue_sha256) in &built_candidates {
        writeln!(
            generated,
            "    CandidateIdentity {{ semantic_candidate_sha256: {:?}, literal_hex: {:?}, implementation_sha256: {:?}, glue_sha256: {:?} }},",
            candidate.semantic_candidate_sha256,
            candidate.literal_hex,
            implementation_sha256,
            glue_sha256,
        )
        .unwrap();
    }
    generated.push_str("];\n");
    fs::write(output.join("generated.rs"), generated).expect("generated runner bindings");
    fs::write(output.join("identity.json"), &identity_bytes).expect("copied identity");

    let receipt = json!({
        "schema": "fre.aot.external-regex-1.12.4-static-runner-build-receipt.v1",
        "identity_sha256": hex(&identity_sha256),
        "runner_revision": revision,
        "runner_source_sha256": hex(&source_identity),
        "target_os": target_os,
        "target_arch": target_arch,
        "backend_name": backend_name,
        "backend_tag": backend_tag,
        "compiler_identity": compiler_identity,
        "manifest_identity": emitted_manifest_identity.expect("one emitted manifest identity"),
        "family_selector": family_selector,
        "minimum_window_bytes": minimum_window_bytes,
        "portable_prefix_candidate_starts": portable_prefix_candidate_starts,
        "plan_identity": plan_identity,
        "analyzer_identity": analyzer_identity,
        "evidence_identity": evidence_identity,
        "timing_permitted": timing_permitted,
        "candidates": built_candidates.iter().map(|(candidate, implementation, glue)| json!({
            "semantic_candidate_sha256": candidate.semantic_candidate_sha256,
            "literal_hex": candidate.literal_hex,
            "implementation_sha256": implementation,
            "glue_sha256": glue,
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
        println!("cargo:rustc-link-arg-bin={BINARY}=-Wl,-z,noexecstack");
        println!("cargo:rustc-link-arg-bin={BINARY}=-Wl,--build-id=none");
        println!(
            "cargo:rustc-link-arg-bin={BINARY}=-Wl,-Map,{}",
            output.join("linked-image.map").display()
        );
    }
}

fn build_macos(candidate: Candidate, backend_tag: u16, selector: u16) -> BuiltCandidate {
    let manifest = MacosAarch64ExactSearchManifestV1::<Span>::candidate_backend_tag(
        SearchCompilePolicyV1::high_fuel(),
        backend_tag,
    )
    .expect("supported macOS candidate backend tag");
    let manifest_identity = *manifest.identity().as_bytes();
    let compiled = plan_and_compile_macos_aarch64_exact_search_v1(
        manifest,
        exact_source(candidate.source),
        RustProfile::default(),
    )
    .expect("macOS external Search object");
    let expectation =
        build_static_search_span_expectation_v1(&compiled).expect("macOS static expectation");
    let glue = publish_search_span_family_qualification_final_image_glue_v1(
        &compiled,
        &expectation,
        selector,
        SearchSpanFinalImageGlueLimitsV1::default(),
    )
    .expect("macOS private-family glue");
    BuiltCandidate {
        implementation: compiled.object().as_bytes().to_vec(),
        glue: glue.object().as_bytes().to_vec(),
        compile_identity: *compiled.receipt().compile_identity().as_bytes(),
        manifest_identity,
    }
}

fn build_linux(candidate: Candidate, backend_tag: u16, selector: u16) -> BuiltCandidate {
    let manifest = LinuxAarch64ExactSearchManifestV1::<Span>::candidate_backend_tag(
        LinuxAarch64SearchCompilePolicyV1::high_fuel(),
        backend_tag,
    )
    .expect("supported Linux candidate backend tag");
    let manifest_identity = *manifest.identity().as_bytes();
    let compiled = plan_and_compile_linux_aarch64_exact_search_v1(
        manifest,
        exact_source(candidate.source),
        RustProfile::default(),
    )
    .expect("Linux external Search object");
    let expectation =
        build_linux_static_search_span_expectation_v1(&compiled).expect("Linux static expectation");
    let glue = publish_linux_search_span_family_qualification_final_image_glue_v1(
        &compiled,
        &expectation,
        selector,
        LinuxSearchSpanFinalImageGlueLimitsV1::default(),
    )
    .expect("Linux private-family glue");
    BuiltCandidate {
        implementation: compiled.object().as_bytes().to_vec(),
        glue: glue.object().as_bytes().to_vec(),
        compile_identity: *compiled.receipt().compile_identity().as_bytes(),
        manifest_identity,
    }
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
        "pub(crate) const LINKED: bool = false;\npub(crate) const TIMING_PERMITTED: bool = false;\npub(crate) const BACKEND_TAG: u16 = 0;\npub(crate) const BACKEND_NAME: &str = \"unresolved\";\npub(crate) const FAMILY_SELECTOR: u16 = 0;\npub(crate) const MINIMUM_WINDOW_BYTES: usize = 1;\npub(crate) const PORTABLE_PREFIX_CANDIDATE_STARTS: usize = 1;\npub(crate) const PLAN_IDENTITY: &str = \"unresolved\";\npub(crate) const ANALYZER_IDENTITY: &str = \"unresolved\";\npub(crate) const EVIDENCE_IDENTITY: &str = \"unresolved\";\npub(crate) const IDENTITY_SHA256: &str = \"unresolved\";\npub(crate) const RUNNER_SOURCE_SHA256: &str = \"unresolved\";\npub(crate) const CANDIDATES: [CandidateIdentity; 4] = [CandidateIdentity { semantic_candidate_sha256: \"\", literal_hex: \"\", implementation_sha256: \"\", glue_sha256: \"\" }; 4];\n",
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

fn hex(bytes: &[u8]) -> String {
    let mut output = String::with_capacity(bytes.len().saturating_mul(2));
    for byte in bytes {
        write!(output, "{byte:02x}").expect("String formatting");
    }
    output
}
