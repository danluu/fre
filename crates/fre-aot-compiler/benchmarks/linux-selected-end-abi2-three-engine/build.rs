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
    LinuxSelectedEndQualificationDeploymentLimitsV2, SelectedEndAotRuntimeAuthorityV2,
    build_linux_selected_end_qualification_bundle_v2,
    build_linux_selected_end_qualification_deployment_v2,
    plan_and_compile_linux_aarch64_selected_end_v2,
};

const BIN: &str = "fre-aot-linux-selected-end-abi2-three-engine";
const SOURCE: &[u8] = b"0123456789abcdef";
const LITERAL: &[u8; 16] = b"0123456789abcdef";
const SOURCE_COMMIT_ENV: &str = "FRE_ABI2_THREE_ENGINE_SOURCE_COMMIT";
const SOURCE_TREE_ENV: &str = "FRE_ABI2_THREE_ENGINE_SOURCE_TREE";
const HELPER_SHA256_ENV: &str = "FRE_ABI2_THREE_ENGINE_HELPER_SHA256";
const PROFILE_ENV: &str = "FRE_ABI2_THREE_ENGINE_PROFILE";
const NATIVE_TARGET_FEATURES_ENV: &str = "FRE_ABI2_THREE_ENGINE_NATIVE_TARGET_FEATURES";
const REQUIRED_PROFILE: &str = "linux-target-cpu-local-v1";
const REQUIRED_TARGET: &str = "aarch64-unknown-linux-gnu";
const REQUIRED_ENCODED_RUSTFLAGS: &str = "-Ctarget-cpu=native\x1f-Cstrip=none";

type DynError = Box<dyn Error>;

fn main() {
    for name in [
        SOURCE_COMMIT_ENV,
        SOURCE_TREE_ENV,
        HELPER_SHA256_ENV,
        PROFILE_ENV,
        NATIVE_TARGET_FEATURES_ENV,
        "CARGO_CFG_PANIC",
        "CARGO_CFG_TARGET_ENV",
        "CARGO_CFG_TARGET_FEATURE",
        "CARGO_ENCODED_RUSTFLAGS",
        "CARGO_INCREMENTAL",
        "CARGO_NET_OFFLINE",
        "CARGO_PROFILE_RELEASE_CODEGEN_UNITS",
        "CARGO_PROFILE_RELEASE_INCREMENTAL",
        "CARGO_PROFILE_RELEASE_LTO",
        "CARGO_PROFILE_RELEASE_OPT_LEVEL",
        "CARGO_PROFILE_RELEASE_PANIC",
        "CARGO_PROFILE_RELEASE_STRIP",
        "HOST",
        "OPT_LEVEL",
        "PROFILE",
        "TARGET",
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
    let deployment_limits = LinuxSelectedEndQualificationDeploymentLimitsV2::default();
    let deployment =
        build_linux_selected_end_qualification_deployment_v2(&bundle, deployment_limits)?;
    deployment.validate(&bundle, deployment_limits)?;
    require(
        deployment.runtime_authority() == SelectedEndAotRuntimeAuthorityV2::Absent
            && deployment.binding().runtime_authority() == SelectedEndAotRuntimeAuthorityV2::Absent
            && deployment.receipt().runtime_authority() == SelectedEndAotRuntimeAuthorityV2::Absent,
        "generated deployment unexpectedly granted runtime authority",
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
    let deployment_receipt_path = output_directory.join("selected-end-deployment-receipt-v2.bin");
    let deployment_binding_path = output_directory.join("linked_selected_end_deployment_v2.rs");
    let contract_path = output_directory.join("selected-end-post-link-contract-v2.tsv");
    let metadata_path = output_directory.join("linked_selected_end_metadata_v2.rs");
    let hot_callsite_path = output_directory.join("linked_selected_end_hot_callsite_v2.rs");

    fs::write(&implementation_path, bundle.compiled().object().as_bytes())?;
    fs::write(&glue_path, bundle.glue().as_bytes())?;
    fs::write(&header_path, bundle.header().as_bytes())?;
    fs::write(&expectation_path, bundle.expectation().as_bytes())?;
    fs::write(
        &compiler_receipt_path,
        bundle.compiled().receipt().canonical_receipt_bytes()?,
    )?;
    fs::write(&bundle_receipt_path, bundle.receipt().canonical_bytes())?;
    fs::write(
        &deployment_receipt_path,
        deployment.receipt().canonical_bytes(),
    )?;
    fs::write(&deployment_binding_path, deployment.binding().as_bytes())?;

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
    let deployment_binding_identity = deployment.binding().identity().to_string();
    let deployment_receipt_identity = deployment.receipt().receipt_identity().to_string();
    let primary_proof_callsite = deployment.binding().primary_callsite_symbol();
    let consumer_hot_callsite =
        format!("fre_aot_search_selected_end_three_engine_hot_callsite_v2_{compile_identity}");

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
        &deployment_binding_identity,
        &deployment_receipt_identity,
        primary_proof_callsite,
        &consumer_hot_callsite,
    )?;
    fs::write(&contract_path, contract)?;

    let metadata = render_benchmark_metadata(
        &source_commit,
        &source_tree,
        &helper_sha256,
        &profile,
        &contract_path,
        &implementation_path,
        &glue_path,
        &deployment_binding_path,
        &deployment_receipt_path,
        &deployment_binding_identity,
        &deployment_receipt_identity,
        &consumer_hot_callsite,
    )?;
    fs::write(&metadata_path, metadata)?;
    fs::write(
        &hot_callsite_path,
        render_benchmark_hot_callsite(&consumer_hot_callsite)?,
    )?;

    for link_input in [&implementation_path, &glue_path] {
        println!("cargo:rustc-link-arg-bin={BIN}={}", link_input.display());
    }
    for retained in [
        symbols.payload().as_str(),
        symbols.metadata().as_str(),
        primary_proof_callsite,
        &consumer_hot_callsite,
    ] {
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
    deployment_binding_identity: &str,
    deployment_receipt_identity: &str,
    primary_proof_callsite: &str,
    consumer_hot_callsite: &str,
) -> Result<String, std::fmt::Error> {
    let mut output = String::new();
    for (key, value) in [
        ("schema", "fre-aot-selected-end-abi2-post-link-contract-v2"),
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
        ("deployment_binding_identity", deployment_binding_identity),
        ("deployment_receipt_identity", deployment_receipt_identity),
        ("wrapper_symbol", wrapper),
        ("primary_proof_callsite_symbol", primary_proof_callsite),
        ("consumer_hot_callsite_symbol", consumer_hot_callsite),
        ("entry_symbol", entry),
        ("payload_symbol", payload),
        ("metadata_symbol", metadata),
        ("required_relocation", "R_AARCH64_CALL26"),
        ("required_final_call", "direct-bl-exact-entry"),
        (
            "primary_aot_hot_route",
            "generated-owned-plan-consumer-loop-direct",
        ),
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
    reason = "benchmark metadata keeps every separately persisted build artifact explicit"
)]
fn render_benchmark_metadata(
    source_commit: &str,
    source_tree: &str,
    helper_sha256: &str,
    profile: &str,
    contract_path: &Path,
    implementation_path: &Path,
    glue_path: &Path,
    deployment_binding_path: &Path,
    deployment_receipt_path: &Path,
    deployment_binding_identity: &str,
    deployment_receipt_identity: &str,
    consumer_hot_callsite: &str,
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
        "pub(super) const DEPLOYMENT_BINDING_PATH: &str = {:?};",
        deployment_binding_path.display().to_string()
    )?;
    writeln!(
        output,
        "pub(super) const DEPLOYMENT_RECEIPT_PATH: &str = {:?};",
        deployment_receipt_path.display().to_string()
    )?;
    writeln!(
        output,
        "pub(super) const DEPLOYMENT_BINDING_IDENTITY: &str = {deployment_binding_identity:?};"
    )?;
    writeln!(
        output,
        "pub(super) const DEPLOYMENT_RECEIPT_IDENTITY: &str = {deployment_receipt_identity:?};"
    )?;
    writeln!(
        output,
        "pub(super) const CONSUMER_HOT_CALLSITE_SYMBOL: &str = {consumer_hot_callsite:?};"
    )?;
    Ok(output)
}

fn render_benchmark_hot_callsite(consumer_hot_callsite: &str) -> Result<String, std::fmt::Error> {
    let mut output = String::new();
    writeln!(
        output,
        "// @generated benchmark adapter; the exact AOT declaration and safe call remain in the compiler deployment binding."
    )?;
    writeln!(
        output,
        "#[allow(unsafe_code, reason = \"the benchmark retains one exact hidden consumer hot-call symbol for post-link inspection\")]\ncore::arch::global_asm!({:?});",
        format!(".hidden {consumer_hot_callsite}"),
    )?;
    writeln!(
        output,
        "#[derive(Clone, Copy, Debug, Eq, PartialEq)]\npub(super) enum AotHotLoopErrorV2 {{\n    Call(fre_aot_static_runtime::StaticSearchSelectedEndCallErrorV2),\n    AccountingMismatch,\n}}\n\n#[allow(unsafe_code, reason = \"the exact export name pins the real measured consumer loop for post-link inspection\")]\n#[unsafe(export_name = {consumer_hot_callsite:?})]\n#[inline(never)]\npub(super) fn run_exact_linked_aot_selected_end_hot_loop_v2<'preflight, 'haystack>(\n    plan_session: &super::aot_deployment::ExactLinkedAotSelectedEndPlanSessionV2<'_, '_>,\n    preflight: fre_kernels::LiteralSearchPreflight<'preflight, 'haystack>,\n    iterations: usize,\n) -> Result<u64, AotHotLoopErrorV2> {{\n    let expected_accounting = preflight.accounting();\n    let mut checksum = 0_u64;\n    for iteration in 0..iterations {{\n        let (matched, accounting) =\n            match super::aot_deployment::search_exact_linked_aot_selected_end_v2(\n                plan_session,\n                core::hint::black_box(preflight),\n            ) {{\n                Ok(result) => result,\n                Err(error) => return Err(AotHotLoopErrorV2::Call(error)),\n            }};\n        if accounting != expected_accounting {{\n            return Err(AotHotLoopErrorV2::AccountingMismatch);\n        }}\n        let span = core::hint::black_box(matched).map(|span| (span.start(), span.end()));\n        checksum = checksum.wrapping_add(super::span_checksum(\n            span,\n            super::usize_u64(iteration),\n        ));\n    }}\n    Ok(core::hint::black_box(checksum))\n}}"
    )?;
    Ok(output)
}

fn require_target() -> Result<(), DynError> {
    require(
        env::var("CARGO_CFG_TARGET_ARCH").as_deref() == Ok("aarch64")
            && env::var("CARGO_CFG_TARGET_OS").as_deref() == Ok("linux")
            && env::var("CARGO_CFG_TARGET_POINTER_WIDTH").as_deref() == Ok("64")
            && env::var("CARGO_CFG_TARGET_ENDIAN").as_deref() == Ok("little")
            && env::var("CARGO_CFG_TARGET_ENV").as_deref() == Ok("gnu")
            && env::var("TARGET").as_deref() == Ok(REQUIRED_TARGET)
            && env::var("HOST").as_deref() == Ok(REQUIRED_TARGET),
        "requires a native little-endian aarch64-unknown-linux-gnu build",
    )?;
    require(
        env::var("PROFILE").as_deref() == Ok("release")
            && env::var("OPT_LEVEL").as_deref() == Ok("3")
            && env::var("CARGO_CFG_PANIC").as_deref() == Ok("abort"),
        "requires the release opt-level=3 panic=abort profile",
    )?;
    require(
        env::var("CARGO_INCREMENTAL").as_deref() == Ok("0"),
        "requires CARGO_INCREMENTAL=0",
    )?;
    require(
        env::var("CARGO_NET_OFFLINE").as_deref() == Ok("true"),
        "requires Cargo offline mode",
    )?;
    require(
        env::var("CARGO_PROFILE_RELEASE_CODEGEN_UNITS").as_deref() == Ok("1")
            && env::var("CARGO_PROFILE_RELEASE_INCREMENTAL").as_deref() == Ok("false")
            && env::var("CARGO_PROFILE_RELEASE_LTO").as_deref() == Ok("thin")
            && env::var("CARGO_PROFILE_RELEASE_OPT_LEVEL").as_deref() == Ok("3")
            && env::var("CARGO_PROFILE_RELEASE_PANIC").as_deref() == Ok("abort")
            && env::var("CARGO_PROFILE_RELEASE_STRIP").as_deref() == Ok("none"),
        "requires the exact checked release-profile overrides",
    )?;
    require(
        env::var("CARGO_ENCODED_RUSTFLAGS").as_deref()
            == Ok(REQUIRED_ENCODED_RUSTFLAGS),
        "requires exact native non-stripping CARGO_ENCODED_RUSTFLAGS",
    )?;
    let target_features = env::var("CARGO_CFG_TARGET_FEATURE")?;
    let expected_target_features = env::var(NATIVE_TARGET_FEATURES_ENV)?;
    let mut actual_features: Vec<&str> = target_features.split(',').collect();
    let mut expected_features: Vec<&str> = expected_target_features.split(',').collect();
    actual_features.sort_unstable();
    expected_features.sort_unstable();
    require(
        !actual_features.is_empty()
            && actual_features.iter().all(|feature| !feature.is_empty())
            && actual_features.windows(2).all(|pair| pair[0] != pair[1])
            && expected_features == actual_features
            && ["neon", "sve", "sve2"]
                .iter()
                .all(|feature| actual_features.binary_search(feature).is_ok()),
        "Cargo target features differ from the checked native rustc probe",
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
