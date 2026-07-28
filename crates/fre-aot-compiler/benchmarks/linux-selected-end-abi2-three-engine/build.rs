use std::{
    env,
    error::Error,
    fmt::Write as _,
    fs,
    path::{Path, PathBuf},
};

use fre::RustProfile;
use fre_aot_compiler::{
    LinuxAarch64SelectedEndManifestV2, LinuxSelectedEndDirectGlueLimitsV2,
    SelectedEndAotRuntimeAuthorityV2, build_linux_selected_end_qualification_bundle_v2,
    plan_and_compile_linux_aarch64_selected_end_v2,
};

const BIN: &str = "fre-aot-linux-selected-end-abi2-three-engine";
const SOURCE: &[u8] = b"0123456789abcdef";
const LITERAL: &[u8; 16] = b"0123456789abcdef";
const SOURCE_COMMIT_ENV: &str = "FRE_ABI2_THREE_ENGINE_SOURCE_COMMIT";
const SOURCE_TREE_ENV: &str = "FRE_ABI2_THREE_ENGINE_SOURCE_TREE";
const HELPER_SHA256_ENV: &str = "FRE_ABI2_THREE_ENGINE_HELPER_SHA256";
const PROFILE_ENV: &str = "FRE_ABI2_THREE_ENGINE_PROFILE";
const REQUIRED_PROFILE: &str = "linux-target-cpu-local-v1";

type DynError = Box<dyn Error>;

fn main() {
    for name in [
        SOURCE_COMMIT_ENV,
        SOURCE_TREE_ENV,
        HELPER_SHA256_ENV,
        PROFILE_ENV,
    ] {
        println!("cargo:rerun-if-env-changed={name}");
    }
    println!("cargo:rerun-if-changed=build.rs");
    println!("cargo:rerun-if-changed=src/main.rs");
    println!("cargo:rerun-if-changed=verify_post_link.py");
    println!("cargo:rerun-if-changed=README.md");
    if let Err(error) = run() {
        panic!("SelectedEnd ABI2 three-engine build refused: {error}");
    }
}

#[allow(
    clippy::too_many_lines,
    reason = "the build transaction keeps all emitted artifacts and linker roots visibly ordered"
)]
fn run() -> Result<(), DynError> {
    require_target()?;
    let source_commit = required_hex(SOURCE_COMMIT_ENV, 40)?;
    let source_tree = required_hex(SOURCE_TREE_ENV, 40)?;
    let helper_sha256 = required_hex(HELPER_SHA256_ENV, 64)?;
    let profile = env::var(PROFILE_ENV)?;
    require(
        profile == REQUIRED_PROFILE,
        "only linux-target-cpu-local-v1 is admitted",
    )?;

    let compiled = plan_and_compile_linux_aarch64_selected_end_v2(
        LinuxAarch64SelectedEndManifestV2::default(),
        SOURCE.to_vec(),
        RustProfile::default(),
    )?;
    let bundle = build_linux_selected_end_qualification_bundle_v2(
        compiled,
        LinuxSelectedEndDirectGlueLimitsV2::default(),
    )?;
    bundle.validate(LinuxSelectedEndDirectGlueLimitsV2::default())?;
    require(
        bundle.runtime_authority() == SelectedEndAotRuntimeAuthorityV2::Absent
            && bundle.compiled().runtime_authority() == SelectedEndAotRuntimeAuthorityV2::Absent
            && bundle.receipt().runtime_authority() == SelectedEndAotRuntimeAuthorityV2::Absent,
        "P2b candidate unexpectedly granted runtime authority",
    )?;
    require(
        bundle.compiled().literal() == LITERAL,
        "compiled literal differs from the benchmark literal",
    )?;
    let requirements = bundle.post_link_disassembly_requirements();
    require(
        requirements.requires_direct_bl()
            && requirements.rejects_blr()
            && requirements.rejects_plt()
            && requirements.rejects_x4_argument()
            && requirements.rejects_result_slot()
            && requirements.requires_identity_suffixed_bindings()
            && requirements.requires_hidden_bindings()
            && !requirements.observation_complete(),
        "P2b post-link obligations changed",
    )?;

    let output_directory = PathBuf::from(env::var_os("OUT_DIR").ok_or("OUT_DIR is absent")?);
    let implementation_path = output_directory.join("selected-end-implementation-v2.o");
    let glue_path = output_directory.join("selected-end-direct-glue-v2.o");
    let header_path = output_directory.join("selected-end-direct-v2.h");
    let expectation_path = output_directory.join("selected-end-expectation-v2.bin");
    let compiler_receipt_path = output_directory.join("selected-end-compiler-receipt-v2.bin");
    let bundle_receipt_path = output_directory.join("selected-end-bundle-receipt-v2.bin");
    let contract_path = output_directory.join("selected-end-post-link-contract-v1.tsv");
    let generated_path = output_directory.join("linked_selected_end_v2.rs");

    fs::write(&implementation_path, bundle.compiled().object().as_bytes())?;
    fs::write(&glue_path, bundle.glue().as_bytes())?;
    fs::write(&header_path, bundle.header().as_bytes())?;
    fs::write(&expectation_path, bundle.expectation().as_bytes())?;
    fs::write(
        &compiler_receipt_path,
        bundle.compiled().receipt().canonical_receipt_bytes()?,
    )?;
    fs::write(&bundle_receipt_path, bundle.receipt().canonical_bytes())?;

    let symbols = bundle.glue().symbols()?;
    let receipt = bundle.compiled().receipt();
    let artifact_identity = hex(receipt.artifact_identity().as_bytes());
    let compile_identity = hex(receipt.compile_identity().as_bytes());
    let implementation_object_identity = hex(receipt.object_identity().as_bytes());
    let glue_object_identity = hex(bundle.glue().object_identity().as_bytes());
    let bundle_identity = hex(bundle.bundle_identity().as_bytes());
    let source_identity = hex(receipt.source_identity().as_bytes());
    let compiler_receipt_identity = hex(receipt.receipt_identity().as_bytes());
    let expectation_identity = hex(bundle.expectation().expectation_identity().as_bytes());

    let contract = render_contract(
        &source_commit,
        &source_tree,
        &helper_sha256,
        &profile,
        symbols.wrapper().as_str(),
        symbols.entry().as_str(),
        symbols.payload().as_str(),
        symbols.metadata().as_str(),
        &artifact_identity,
        &compile_identity,
        &implementation_object_identity,
        &glue_object_identity,
        &bundle_identity,
        &source_identity,
        &compiler_receipt_identity,
        &expectation_identity,
    )?;
    fs::write(&contract_path, contract)?;

    let generated = render_rust_bindings(
        &source_commit,
        &source_tree,
        &helper_sha256,
        &profile,
        &contract_path,
        &implementation_path,
        &glue_path,
        symbols.wrapper().as_str(),
        symbols.entry().as_str(),
        symbols.payload().as_str(),
        symbols.metadata().as_str(),
        receipt.artifact_identity().as_bytes(),
        receipt.compile_identity().as_bytes(),
        receipt.object_identity().as_bytes(),
        bundle.glue().object_identity().as_bytes(),
        bundle.bundle_identity().as_bytes(),
    )?;
    fs::write(&generated_path, generated)?;

    for link_input in [&implementation_path, &glue_path] {
        println!("cargo:rustc-link-arg-bin={BIN}={}", link_input.display());
    }
    for retained in [symbols.payload().as_str(), symbols.metadata().as_str()] {
        println!("cargo:rustc-link-arg-bin={BIN}=-Wl,--undefined={retained}");
    }
    println!("cargo:rustc-link-arg-bin={BIN}=-Wl,-z,separate-code");
    println!("cargo:rustc-link-arg-bin={BIN}=-Wl,-z,noexecstack");
    println!("cargo:rustc-link-arg-bin={BIN}=-Wl,-z,now");
    Ok(())
}

#[allow(
    clippy::too_many_arguments,
    reason = "the closed contract lists every independently inspectable identity and symbol"
)]
fn render_contract(
    source_commit: &str,
    source_tree: &str,
    helper_sha256: &str,
    profile: &str,
    wrapper: &str,
    entry: &str,
    payload: &str,
    metadata: &str,
    artifact_identity: &str,
    compile_identity: &str,
    implementation_object_identity: &str,
    glue_object_identity: &str,
    bundle_identity: &str,
    source_identity: &str,
    compiler_receipt_identity: &str,
    expectation_identity: &str,
) -> Result<String, std::fmt::Error> {
    let mut output = String::new();
    for (key, value) in [
        ("schema", "fre-aot-selected-end-abi2-post-link-contract-v1"),
        ("evidence_class", "diagnostic-nonpromotion"),
        ("promotion_authority", "absent"),
        ("runtime_authority", "absent"),
        ("source_commit", source_commit),
        ("source_tree", source_tree),
        ("helper_sha256", helper_sha256),
        ("profile", profile),
        ("target", "aarch64-unknown-linux-little-endian-lp64"),
        ("backend", "tag21-sve2-fixed16"),
        ("abi", "selected-end-register-v2"),
        ("literal_hex", "30313233343536373839616263646566"),
        ("source_identity", source_identity),
        ("artifact_identity", artifact_identity),
        ("compile_identity", compile_identity),
        (
            "implementation_object_identity",
            implementation_object_identity,
        ),
        ("glue_object_identity", glue_object_identity),
        ("compiler_receipt_identity", compiler_receipt_identity),
        ("expectation_identity", expectation_identity),
        ("bundle_identity", bundle_identity),
        ("wrapper_symbol", wrapper),
        ("entry_symbol", entry),
        ("payload_symbol", payload),
        ("metadata_symbol", metadata),
        ("required_relocation", "R_AARCH64_CALL26"),
        ("required_final_call", "direct-bl-exact-entry"),
        ("primary_aot_hot_route", "exact-entry-direct"),
        (
            "qualification_wrapper_route",
            "linked-validated-diagnostic-only",
        ),
        ("reject_indirect_branch", "blr"),
        ("reject_plt", "true"),
        ("reject_x4_argument", "true"),
        ("result_slot_bytes", "0"),
        ("required_sve_vector_bytes", "16"),
        ("aot_compiler_cost_scope", "offline-excluded"),
        ("aot_linker_cost_scope", "offline-excluded"),
        ("post_link_observation", "pending"),
    ] {
        writeln!(output, "{key}\t{value}")?;
    }
    Ok(output)
}

#[allow(
    clippy::too_many_arguments,
    reason = "generated code binds the complete exact candidate namespace and identity tuple"
)]
fn render_rust_bindings(
    source_commit: &str,
    source_tree: &str,
    helper_sha256: &str,
    profile: &str,
    contract_path: &Path,
    implementation_path: &Path,
    glue_path: &Path,
    wrapper: &str,
    entry: &str,
    payload: &str,
    metadata: &str,
    artifact_identity: &[u8; 32],
    compile_identity: &[u8; 32],
    implementation_object_identity: &[u8; 32],
    glue_object_identity: &[u8; 32],
    bundle_identity: &[u8; 32],
) -> Result<String, std::fmt::Error> {
    let mut output = String::new();
    writeln!(
        output,
        "pub(super) const BOUND_SOURCE_COMMIT: &str = {source_commit:?};"
    )?;
    writeln!(
        output,
        "pub(super) const BOUND_SOURCE_TREE: &str = {source_tree:?};"
    )?;
    writeln!(
        output,
        "pub(super) const BOUND_HELPER_SHA256: &str = {helper_sha256:?};"
    )?;
    writeln!(
        output,
        "pub(super) const BOUND_PROFILE: &str = {profile:?};"
    )?;
    writeln!(
        output,
        "pub(super) const POST_LINK_CONTRACT_PATH: &str = {:?};",
        contract_path.display().to_string()
    )?;
    writeln!(
        output,
        "pub(super) const IMPLEMENTATION_OBJECT_PATH: &str = {:?};",
        implementation_path.display().to_string()
    )?;
    writeln!(
        output,
        "pub(super) const DIRECT_GLUE_OBJECT_PATH: &str = {:?};",
        glue_path.display().to_string()
    )?;
    writeln!(
        output,
        "pub(super) const WRAPPER_SYMBOL: &str = {wrapper:?};"
    )?;
    writeln!(output, "pub(super) const ENTRY_SYMBOL: &str = {entry:?};")?;
    writeln!(
        output,
        "pub(super) const PAYLOAD_SYMBOL: &str = {payload:?};"
    )?;
    writeln!(
        output,
        "pub(super) const METADATA_SYMBOL: &str = {metadata:?};"
    )?;
    writeln!(
        output,
        "pub(super) const AOT_ARTIFACT_IDENTITY: [u8; 32] = {artifact_identity:?};"
    )?;
    writeln!(
        output,
        "pub(super) const AOT_COMPILE_IDENTITY: [u8; 32] = {compile_identity:?};"
    )?;
    writeln!(
        output,
        "pub(super) const AOT_IMPLEMENTATION_OBJECT_IDENTITY: [u8; 32] = {implementation_object_identity:?};"
    )?;
    writeln!(
        output,
        "pub(super) const AOT_GLUE_OBJECT_IDENTITY: [u8; 32] = {glue_object_identity:?};"
    )?;
    writeln!(
        output,
        "pub(super) const AOT_BUNDLE_IDENTITY: [u8; 32] = {bundle_identity:?};"
    )?;
    writeln!(
        output,
        "#[allow(unsafe_code, reason = \"generated FFI declares only the sealed exact ABI2 symbols\")]\nunsafe extern \"C\" {{\n    #[link_name = {entry:?}]\n    fn exact_linked_aot_selected_end_entry_v2(haystack: *const u8, haystack_len: usize, window_start: usize, window_end: usize) -> usize;\n    #[link_name = {wrapper:?}]\n    fn exact_linked_aot_selected_end_qualification_wrapper_v2(haystack: *const u8, haystack_len: usize, window_start: usize, window_end: usize) -> usize;\n}}"
    )?;
    writeln!(
        output,
        "#[allow(unsafe_code, reason = \"the checked AOT session guards this exact ABI2 call\")]\n#[inline(always)]\npub(super) fn call_exact_linked_aot_selected_end_entry_v2(_session: &super::AotThreadSession<'_>, haystack: &[u8], window_start: usize, window_end: usize) -> usize {{\n    // SAFETY: the private generated entry requires the non-transferable\n    // AotThreadSession constructed after one same-thread tag21 VL16 check;\n    // its caller also supplies scalar-preflighted bounds. The exact linked\n    // entry has the sealed four-argument ABI2 contract and no result slot.\n    unsafe {{ exact_linked_aot_selected_end_entry_v2(haystack.as_ptr(), haystack.len(), window_start, window_end) }}\n}}\n\n#[allow(unsafe_code, reason = \"the checked AOT session guards this diagnostic ABI2 call\")]\n#[inline(always)]\npub(super) fn call_exact_linked_aot_selected_end_qualification_wrapper_v2(_session: &super::AotThreadSession<'_>, haystack: &[u8], window_start: usize, window_end: usize) -> usize {{\n    // SAFETY: this diagnostic-only route requires the same private checked\n    // thread token and scalar-preflighted inputs as the primary direct route.\n    unsafe {{ exact_linked_aot_selected_end_qualification_wrapper_v2(haystack.as_ptr(), haystack.len(), window_start, window_end) }}\n}}"
    )?;
    Ok(output)
}

fn require_target() -> Result<(), DynError> {
    require(
        env::var("CARGO_CFG_TARGET_ARCH").as_deref() == Ok("aarch64")
            && env::var("CARGO_CFG_TARGET_OS").as_deref() == Ok("linux")
            && env::var("CARGO_CFG_TARGET_POINTER_WIDTH").as_deref() == Ok("64")
            && env::var("CARGO_CFG_TARGET_ENDIAN").as_deref() == Ok("little"),
        "requires little-endian Linux/AArch64 LP64",
    )
}

fn required_hex(name: &str, width: usize) -> Result<String, DynError> {
    let value = env::var(name)?;
    require(
        value.len() == width
            && value.bytes().all(|byte| byte.is_ascii_hexdigit())
            && value.bytes().all(|byte| !byte.is_ascii_uppercase())
            && value.bytes().any(|byte| byte != b'0'),
        &format!("{name} is not canonical nonzero lowercase hexadecimal"),
    )?;
    Ok(value)
}

fn require(condition: bool, message: &str) -> Result<(), DynError> {
    if condition {
        Ok(())
    } else {
        Err(message.into())
    }
}

fn hex(bytes: &[u8; 32]) -> String {
    let mut output = String::with_capacity(64);
    for byte in bytes {
        write!(output, "{byte:02x}").expect("writing to String cannot fail");
    }
    output
}
