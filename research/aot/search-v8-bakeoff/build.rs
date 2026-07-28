use std::{
    env,
    fmt::Write as _,
    fs,
    path::{Path, PathBuf},
};

use fre::{PlanKind, PortableBuilder, RustProfile};
use fre_aot_compiler::{
    MacosAarch64ExactSearchManifestV1, SearchAotRuntimeAuthorityV1,
    plan_and_compile_macos_aarch64_exact_search_v1,
};
use fre_aot_macho::{C_HEADER, ObjectLimits, inspect_object, validate_search_object};
use fre_jit_aarch64::{BackendVersion, EmitLimits, SearchBackendPolicy, emit_with_backend};
use fre_kernel_ir::{AnchorFlags, Span, ValidateLimits, build_exact_literal};
use sha2::{Digest, Sha256};

const PATTERN: &str = "0123456789abcdef";
const SOURCE_MANIFEST: &str = "benchmark-source-files.txt";
const BINARY: &str = "fre-search-v8-bakeoff";
const RECEIPT_SCHEMA: &str = "fre-search-v8-bakeoff-build-receipt-v2";
const SOURCE_IDENTITY_DOMAIN: &[u8] = b"FRE-SEARCH-V8-BAKEOFF-SOURCE\0\x01";

fn main() {
    let manifest_dir = required_path("CARGO_MANIFEST_DIR");
    let output_dir = required_path("OUT_DIR");
    let revision = required_revision();
    require_target();

    let source_identity =
        benchmark_source_identity(&manifest_dir).expect("benchmark source identity");
    let mut compiler_source = Vec::new();
    compiler_source
        .try_reserve_exact(PATTERN.len())
        .expect("fixed compiler source allocation");
    assert_eq!(
        compiler_source.capacity(),
        PATTERN.len(),
        "compiler source capacity must be deterministic"
    );
    compiler_source.extend_from_slice(PATTERN.as_bytes());
    let mut compiler_profile = RustProfile::default();
    compiler_profile.options.unicode = false;
    let compiled = plan_and_compile_macos_aarch64_exact_search_v1(
        MacosAarch64ExactSearchManifestV1::<Span>::default(),
        compiler_source,
        compiler_profile,
    )
    .expect("source-first Search V8 compiler object");
    assert_eq!(
        compiled.runtime_authority(),
        SearchAotRuntimeAuthorityV1::Absent
    );
    assert_eq!(
        compiled.receipt().runtime_authority(),
        SearchAotRuntimeAuthorityV1::Absent
    );

    let portable = PortableBuilder::new(PATTERN)
        .unicode(false)
        .build()
        .expect("fixed portable exact-literal candidate");
    assert_eq!(portable.build_report().plan, PlanKind::ExactLiteral);
    let candidate = portable
        .exact_literal_search_aot_candidate()
        .expect("authenticated fixed-policy exact-literal AOT candidate");
    assert_eq!(candidate.source(), PATTERN);
    assert_eq!(candidate.literal(), PATTERN.as_bytes());

    let program = build_exact_literal::<Span>(
        candidate.literal(),
        AnchorFlags::default(),
        ValidateLimits::default(),
    )
    .expect("fixed Span Kernel IR");
    let image = emit_with_backend(
        &program,
        SearchBackendPolicy::AsimdV8,
        EmitLimits::default(),
    )
    .expect("fixed Search V8 image");
    assert_eq!(image.backend_version(), BackendVersion::SEARCH_V8);
    assert_eq!(image.source_identity(), program.cache_identity());

    let semantic_identity = *candidate.semantic_binding_identity().as_bytes();
    let compiler_receipt = compiled.receipt();
    assert_eq!(
        compiler_receipt.semantic_binding_identity().as_bytes(),
        &semantic_identity
    );
    assert_ne!(
        compiler_receipt.binding_identity().as_bytes(),
        &semantic_identity,
        "compiler object binding must remain domain-separated"
    );
    assert_eq!(
        compiler_receipt
            .accounting()
            .candidate_identity_bytes_hashed(),
        candidate.semantic_identity_bytes_hashed()
    );
    assert_eq!(compiler_receipt.kir_identity(), program.cache_identity());
    assert_eq!(
        compiler_receipt.native_artifact_identity(),
        image.artifact_identity()
    );
    let object = compiled.object();
    let validated = validate_search_object(
        &image,
        compiler_receipt.binding_identity(),
        object.as_bytes(),
        ObjectLimits::default(),
    )
    .expect("fresh strict compiler-object validation");
    let inspected = inspect_object(object.as_bytes(), ObjectLimits::default())
        .expect("fresh strict object inspection");
    assert_eq!(validated.inspection, inspected);
    assert_eq!(
        compiler_receipt
            .validate_object(object.as_bytes(), ObjectLimits::default())
            .expect("typed compiler receipt reopens its exact object"),
        inspected
    );
    let canonical_compiler_receipt = compiler_receipt
        .canonical_bytes()
        .expect("canonical Search compiler receipt");
    assert_eq!(
        sha256(&canonical_compiler_receipt),
        *compiler_receipt.receipt_identity().as_bytes()
    );
    let mut expected_payload = Vec::with_capacity(
        usize::try_from(image.layout().total_mapped_bytes).expect("bounded mapped image bytes"),
    );
    expected_payload.extend_from_slice(image.code());
    expected_payload.resize(
        usize::try_from(image.layout().rodata_from_code_start).expect("bounded rodata offset"),
        0,
    );
    expected_payload.extend_from_slice(image.rodata());
    assert_eq!(inspected.payload(), expected_payload.as_slice());

    let object_path = output_dir.join("fre_search_v8_span.o");
    let receipt_path = output_dir.join("fre_search_v8_span_receipt.tsv");
    let bindings_path = output_dir.join("fre_search_v8_span_bindings.rs");
    let header_path = output_dir.join("fre_search_v8_span.h");
    let link_map_path = output_dir.join("fre_search_v8_span.map");
    fs::write(&object_path, object.as_bytes()).expect("write deterministic Search object");

    let metadata = object.metadata();
    let symbols = object.exported_symbols();
    let metadata_sha256 = sha256(inspected.metadata_bytes());
    let object_sha256 = sha256(object.as_bytes());
    assert_eq!(&object_sha256, object.object_identity().as_bytes());
    assert_eq!(metadata.payload_sha256(), &sha256(inspected.payload()));
    assert_eq!(
        metadata.source_identity(),
        program.cache_identity().as_bytes()
    );
    assert_eq!(
        metadata.artifact_identity(),
        image.artifact_identity().as_bytes()
    );
    assert!(
        compiler_receipt
            .binding_identity()
            .matches_claim(metadata.claimed_binding_identity())
    );
    assert!(
        object
            .compile_identity()
            .matches_claim(metadata.claimed_compile_identity())
    );

    let build_receipt = render_receipt(
        &revision,
        &source_identity,
        compiler_receipt
            .accounting()
            .candidate_identity_bytes_hashed(),
        &semantic_identity,
        compiler_receipt.binding_identity().as_bytes(),
        compiler_receipt.receipt_identity().as_bytes(),
        program.cache_identity().as_bytes(),
        image.artifact_identity().as_bytes(),
        object.compile_identity().as_bytes(),
        object.object_identity().as_bytes(),
        metadata.payload_sha256(),
        &metadata_sha256,
        object.as_bytes().len(),
        metadata,
        &object_path,
        &link_map_path,
        symbols.entry().as_str(),
        symbols.payload().as_str(),
        symbols.metadata().as_str(),
    );
    fs::write(&receipt_path, build_receipt.as_bytes()).expect("write build receipt");
    fs::write(
        &bindings_path,
        render_bindings(
            &revision,
            &source_identity,
            &semantic_identity,
            compiler_receipt.binding_identity().as_bytes(),
            compiler_receipt.receipt_identity().as_bytes(),
            program.cache_identity().as_bytes(),
            image.artifact_identity().as_bytes(),
            object.compile_identity().as_bytes(),
            object.object_identity().as_bytes(),
            metadata.payload_sha256(),
            &metadata_sha256,
            object.as_bytes().len(),
            usize::try_from(metadata.payload_bytes()).expect("bounded payload bytes"),
            symbols.entry().as_str(),
            symbols.payload().as_str(),
            symbols.metadata().as_str(),
            &receipt_path,
            &object_path,
            &link_map_path,
        )
        .as_bytes(),
    )
    .expect("write identity-bound Rust bindings");
    fs::write(
        &header_path,
        render_header(
            symbols.entry().as_str(),
            symbols.payload().as_str(),
            symbols.metadata().as_str(),
        )
        .as_bytes(),
    )
    .expect("write identity-bound C header");

    println!("cargo:rerun-if-env-changed=FRE_SEARCH_V8_SUBJECT_REVISION");
    println!("cargo:rerun-if-changed={SOURCE_MANIFEST}");
    for source in source_manifest(&manifest_dir).expect("source manifest") {
        println!("cargo:rerun-if-changed={source}");
    }
    println!(
        "cargo:rustc-link-arg-bin={BINARY}={}",
        object_path.display()
    );
    println!("cargo:rustc-link-arg-bin={BINARY}=-Wl,-segprot,__TEXT,rx,rx");
    println!("cargo:rustc-link-arg-bin={BINARY}=-Wl,-segprot,__FRE_CONST,r,r");
    println!("cargo:rustc-link-arg-bin={BINARY}=-Wl,-reproducible");
    println!(
        "cargo:rustc-link-arg-bin={BINARY}=-Wl,-map,{}",
        link_map_path.display()
    );
}

fn required_path(name: &str) -> PathBuf {
    PathBuf::from(env::var_os(name).unwrap_or_else(|| panic!("missing {name}")))
}

fn required_revision() -> String {
    let revision =
        env::var("FRE_SEARCH_V8_SUBJECT_REVISION").expect("source-bound subject revision");
    assert!(
        revision.len() == 40
            && revision
                .bytes()
                .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase()),
        "subject revision must be exactly 40 lowercase hexadecimal digits"
    );
    revision
}

fn require_target() {
    assert_eq!(
        env::var("CARGO_CFG_TARGET_OS").as_deref(),
        Ok("macos"),
        "Search V8 Mach-O bakeoff requires macOS"
    );
    assert_eq!(
        env::var("CARGO_CFG_TARGET_ARCH").as_deref(),
        Ok("aarch64"),
        "Search V8 Mach-O bakeoff requires AArch64"
    );
    assert_eq!(
        env::var("CARGO_CFG_TARGET_ENDIAN").as_deref(),
        Ok("little"),
        "Search V8 Mach-O bakeoff requires little endian"
    );
    assert_eq!(
        env::var("CARGO_CFG_TARGET_POINTER_WIDTH").as_deref(),
        Ok("64"),
        "Search V8 Mach-O bakeoff requires 64-bit pointers"
    );
}

fn source_manifest(manifest_dir: &Path) -> Result<Vec<String>, String> {
    let manifest_path = manifest_dir.join(SOURCE_MANIFEST);
    let text = fs::read_to_string(&manifest_path)
        .map_err(|error| format!("read {}: {error}", manifest_path.display()))?;
    if text.is_empty() || !text.ends_with('\n') {
        return Err("source manifest must be nonempty and newline terminated".to_owned());
    }
    let mut names = Vec::new();
    for line in text.lines() {
        if line.is_empty()
            || line.starts_with('/')
            || line.contains('\\')
            || line.split('/').any(|part| matches!(part, "" | "." | ".."))
        {
            return Err(format!("invalid source manifest entry {line:?}"));
        }
        names.push(line.to_owned());
    }
    let mut sorted = names.clone();
    sorted.sort();
    sorted.dedup();
    if names != sorted {
        return Err("source manifest must be strictly sorted and unique".to_owned());
    }
    Ok(names)
}

fn benchmark_source_identity(manifest_dir: &Path) -> Result<[u8; 32], String> {
    let names = source_manifest(manifest_dir)?;
    let mut hasher = Sha256::new();
    hasher.update(SOURCE_IDENTITY_DOMAIN);
    for name in names {
        let path = manifest_dir.join(&name);
        let metadata = fs::symlink_metadata(&path)
            .map_err(|error| format!("metadata {}: {error}", path.display()))?;
        if !metadata.is_file() || metadata.file_type().is_symlink() || metadata.len() > (1 << 20) {
            return Err(format!("source is not one bounded regular file: {name}"));
        }
        let bytes = fs::read(&path).map_err(|error| format!("read {name}: {error}"))?;
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

fn sha256(bytes: &[u8]) -> [u8; 32] {
    Sha256::digest(bytes).into()
}

#[allow(clippy::too_many_arguments)]
fn render_receipt(
    revision: &str,
    benchmark_source_identity: &[u8; 32],
    semantic_identity_bytes_hashed: u64,
    semantic_identity: &[u8; 32],
    binding_identity: &[u8; 32],
    compiler_receipt_identity: &[u8; 32],
    source_identity: &[u8; 32],
    artifact_identity: &[u8; 32],
    compile_identity: &[u8; 32],
    object_identity: &[u8; 32],
    payload_sha256: &[u8; 32],
    metadata_sha256: &[u8; 32],
    object_bytes: usize,
    metadata: fre_aot_macho::MetadataV1,
    object_path: &Path,
    link_map_path: &Path,
    entry_symbol: &str,
    payload_symbol: &str,
    metadata_symbol: &str,
) -> String {
    let mut output = String::new();
    for (key, value) in [
        ("schema", RECEIPT_SCHEMA.to_owned()),
        ("subject_revision", revision.to_owned()),
        ("benchmark_source_sha256", hex(benchmark_source_identity)),
        (
            "semantic_identity_bytes_hashed",
            semantic_identity_bytes_hashed.to_string(),
        ),
        ("semantic_identity", hex(semantic_identity)),
        ("binding_identity", hex(binding_identity)),
        ("compiler_receipt_identity", hex(compiler_receipt_identity)),
        ("source_identity", hex(source_identity)),
        ("artifact_identity", hex(artifact_identity)),
        ("compile_identity", hex(compile_identity)),
        ("object_identity", hex(object_identity)),
        ("payload_sha256", hex(payload_sha256)),
        ("metadata_sha256", hex(metadata_sha256)),
        ("literal_hex", hex(PATTERN.as_bytes())),
        ("literal_bytes", PATTERN.len().to_string()),
        ("backend_version", metadata.backend_version().to_string()),
        ("output_kind", metadata.output_kind().to_string()),
        ("object_bytes", object_bytes.to_string()),
        ("payload_bytes", metadata.payload_bytes().to_string()),
        ("metadata_bytes", metadata.record_bytes().to_string()),
        ("code_bytes", metadata.code_bytes().to_string()),
        ("rodata_offset", metadata.rodata_offset().to_string()),
        ("rodata_bytes", metadata.rodata_bytes().to_string()),
        ("entry_symbol", entry_symbol.to_owned()),
        ("payload_symbol", payload_symbol.to_owned()),
        ("metadata_symbol", metadata_symbol.to_owned()),
        ("object_path", object_path.display().to_string()),
        ("link_map_path", link_map_path.display().to_string()),
        ("target", "aarch64-apple-macos".to_owned()),
        (
            "aot_authority",
            "benchmark-local-raw-abi-no-adoption".to_owned(),
        ),
        ("qualification_state", "candidate".to_owned()),
        ("production_activation", "absent".to_owned()),
    ] {
        writeln!(output, "{key}\t{value}").expect("String write");
    }
    output
}

#[allow(clippy::too_many_arguments)]
fn render_bindings(
    revision: &str,
    benchmark_source_identity: &[u8; 32],
    semantic_identity: &[u8; 32],
    binding_identity: &[u8; 32],
    compiler_receipt_identity: &[u8; 32],
    source_identity: &[u8; 32],
    artifact_identity: &[u8; 32],
    compile_identity: &[u8; 32],
    object_identity: &[u8; 32],
    payload_sha256: &[u8; 32],
    metadata_sha256: &[u8; 32],
    object_bytes: usize,
    payload_bytes: usize,
    entry_symbol: &str,
    payload_symbol: &str,
    metadata_symbol: &str,
    receipt_path: &Path,
    object_path: &Path,
    link_map_path: &Path,
) -> String {
    format!(
        r#"pub const SUBJECT_REVISION: &str = {revision:?};
pub const BENCHMARK_SOURCE_IDENTITY: [u8; 32] = {benchmark_source_identity:?};
pub const SEMANTIC_IDENTITY: [u8; 32] = {semantic_identity:?};
pub const BINDING_IDENTITY: [u8; 32] = {binding_identity:?};
pub const COMPILER_RECEIPT_IDENTITY: [u8; 32] = {compiler_receipt_identity:?};
pub const SOURCE_IDENTITY: [u8; 32] = {source_identity:?};
pub const ARTIFACT_IDENTITY: [u8; 32] = {artifact_identity:?};
pub const COMPILE_IDENTITY: [u8; 32] = {compile_identity:?};
pub const OBJECT_IDENTITY: [u8; 32] = {object_identity:?};
pub const PAYLOAD_SHA256: [u8; 32] = {payload_sha256:?};
pub const METADATA_SHA256: [u8; 32] = {metadata_sha256:?};
pub const OBJECT_BYTES: usize = {object_bytes};
pub const PAYLOAD_BYTES: usize = {payload_bytes};
pub const ENTRY_SYMBOL: &str = {entry_symbol:?};
pub const PAYLOAD_SYMBOL: &str = {payload_symbol:?};
pub const METADATA_SYMBOL: &str = {metadata_symbol:?};
pub const RECEIPT_PATH: &str = {receipt_path:?};
pub const OBJECT_PATH: &str = {object_path:?};
pub const LINK_MAP_PATH: &str = {link_map_path:?};

unsafe extern "C" {{
    #[link_name = {entry_symbol:?}]
    pub(super) fn linked_search_v8_span(
        haystack: *const u8,
        haystack_len: usize,
        window_start: usize,
        window_end: usize,
        result: *mut super::RawSpan,
    ) -> u64;
}}
"#,
    )
}

fn render_header(entry_symbol: &str, payload_symbol: &str, metadata_symbol: &str) -> String {
    let mut output = C_HEADER.to_owned();
    writeln!(output, "#ifndef FRE_SEARCH_V8_SPAN_BINDINGS_H").expect("String write");
    writeln!(output, "#define FRE_SEARCH_V8_SPAN_BINDINGS_H").expect("String write");
    writeln!(output, "#if defined(__cplusplus)").expect("String write");
    writeln!(output, "extern \"C\" {{").expect("String write");
    writeln!(output, "#endif").expect("String write");
    writeln!(
        output,
        "extern uint64_t {entry_symbol}(const uint8_t *, size_t, size_t, size_t, struct fre_aot_search_result_v1 *);"
    )
    .expect("String write");
    writeln!(output, "extern const uint8_t {payload_symbol}[];").expect("String write");
    writeln!(
        output,
        "extern const struct fre_aot_metadata_v1 {metadata_symbol};"
    )
    .expect("String write");
    writeln!(output, "#if defined(__cplusplus)").expect("String write");
    writeln!(output, "}}").expect("String write");
    writeln!(output, "#endif").expect("String write");
    writeln!(output, "#define FRE_SEARCH_V8_SPAN_ENTRY {entry_symbol}").expect("String write");
    writeln!(
        output,
        "#define FRE_SEARCH_V8_SPAN_PAYLOAD {payload_symbol}"
    )
    .expect("String write");
    writeln!(
        output,
        "#define FRE_SEARCH_V8_SPAN_METADATA {metadata_symbol}"
    )
    .expect("String write");
    writeln!(output, "#endif").expect("String write");
    output
}

fn hex(bytes: &[u8]) -> String {
    let mut output = String::with_capacity(bytes.len().saturating_mul(2));
    for byte in bytes {
        write!(output, "{byte:02x}").expect("String write");
    }
    output
}
