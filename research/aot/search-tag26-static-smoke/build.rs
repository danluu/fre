use std::{env, fmt::Write as _, fs, path::PathBuf};

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
use fre_aot_search_contract::SEARCH_BACKEND_ASIMD_TAG26_V1;
use fre_kernel_ir::Span;

const BINARY: &str = "fre-search-tag26-static-smoke";
const FAIL_CLOSED_TEST_SELECTOR: u16 = 11;
const LITERAL: &[u8] = b"needle";
const GLUE_SYMBOL_PREFIX: &str = "fre_aot_search_span_glue_v1_";

struct Artifacts {
    implementation: Vec<u8>,
    glue: Vec<u8>,
    compile_identity: String,
}

fn main() {
    println!("cargo:rerun-if-changed=build.rs");
    let target_arch = env::var("CARGO_CFG_TARGET_ARCH").expect("target architecture");
    let target_os = env::var("CARGO_CFG_TARGET_OS").expect("target operating system");
    assert_eq!(
        target_arch, "aarch64",
        "tag26 static smoke requires AArch64"
    );
    assert!(
        matches!(target_os.as_str(), "macos" | "linux"),
        "tag26 static smoke requires macOS or Linux"
    );

    let artifacts = if target_os == "macos" {
        build_macos()
    } else {
        build_linux()
    };
    let output = PathBuf::from(env::var_os("OUT_DIR").expect("build output directory"));
    let implementation_path = output.join("search-tag26-implementation.o");
    let glue_path = output.join("search-tag26-family-glue.o");
    fs::write(&implementation_path, artifacts.implementation).expect("implementation object");
    fs::write(&glue_path, artifacts.glue).expect("family glue object");
    println!(
        "cargo:rustc-link-arg-bin={BINARY}={}",
        implementation_path.display()
    );
    println!("cargo:rustc-link-arg-bin={BINARY}={}", glue_path.display());
    if target_os == "macos" {
        println!("cargo:rustc-link-arg-bin={BINARY}=-Wl,-segprot,__TEXT,rx,rx");
        println!("cargo:rustc-link-arg-bin={BINARY}=-Wl,-segprot,__FRE_CONST,r,r");
        println!("cargo:rustc-link-arg-bin={BINARY}=-Wl,-reproducible");
    } else {
        println!("cargo:rustc-link-arg-bin={BINARY}=-Wl,-z,noexecstack");
        println!("cargo:rustc-link-arg-bin={BINARY}=-Wl,--build-id=none");
    }

    let mut generated = String::new();
    generated.push_str(
        "#[allow(unsafe_code, reason = \"receipt-bound private family glue is linked by exact symbol identity\")]\nunsafe extern \"C\" {\n",
    );
    writeln!(
        generated,
        "    #[link_name = {:?}] fn invoke_tag26_glue(output: *mut fre_aot_static_runtime::RawStaticSearchSpanAdoptionOutputV1) -> u32;",
        format!("{GLUE_SYMBOL_PREFIX}{}", artifacts.compile_identity)
    )
    .expect("generated declaration");
    generated.push_str(
        "}\n#[allow(unsafe_code, unsafe_op_in_unsafe_fn, reason = \"caller upholds the private adapter output-slot contract\")]\npub(crate) unsafe fn invoke(output: *mut fre_aot_static_runtime::RawStaticSearchSpanAdoptionOutputV1) -> u32 { unsafe { invoke_tag26_glue(output) } }\n",
    );
    fs::write(output.join("generated.rs"), generated).expect("generated glue binding");
}

fn build_macos() -> Artifacts {
    let manifest = MacosAarch64ExactSearchManifestV1::<Span>::candidate_backend_tag(
        SearchCompilePolicyV1::high_fuel(),
        SEARCH_BACKEND_ASIMD_TAG26_V1,
    )
    .expect("macOS tag26 candidate manifest");
    let compiled = plan_and_compile_macos_aarch64_exact_search_v1(
        manifest,
        LITERAL.to_vec(),
        RustProfile::default(),
    )
    .expect("macOS tag26 implementation object");
    let expectation =
        build_static_search_span_expectation_v1(&compiled).expect("macOS neutral expectation");
    let glue = publish_search_span_family_qualification_final_image_glue_v1(
        &compiled,
        &expectation,
        FAIL_CLOSED_TEST_SELECTOR,
        SearchSpanFinalImageGlueLimitsV1::default(),
    )
    .expect("macOS tag26 private family glue");
    Artifacts {
        implementation: compiled.object().as_bytes().to_vec(),
        glue: glue.object().as_bytes().to_vec(),
        compile_identity: compiled.receipt().compile_identity().to_string(),
    }
}

fn build_linux() -> Artifacts {
    let manifest = LinuxAarch64ExactSearchManifestV1::<Span>::candidate_backend_tag(
        LinuxAarch64SearchCompilePolicyV1::high_fuel(),
        SEARCH_BACKEND_ASIMD_TAG26_V1,
    )
    .expect("Linux tag26 candidate manifest");
    let compiled = plan_and_compile_linux_aarch64_exact_search_v1(
        manifest,
        LITERAL.to_vec(),
        RustProfile::default(),
    )
    .expect("Linux tag26 implementation object");
    let expectation = build_linux_static_search_span_expectation_v1(&compiled)
        .expect("Linux neutral expectation");
    let glue = publish_linux_search_span_family_qualification_final_image_glue_v1(
        &compiled,
        &expectation,
        FAIL_CLOSED_TEST_SELECTOR,
        LinuxSearchSpanFinalImageGlueLimitsV1::default(),
    )
    .expect("Linux tag26 private family glue");
    Artifacts {
        implementation: compiled.object().as_bytes().to_vec(),
        glue: glue.object().as_bytes().to_vec(),
        compile_identity: compiled.receipt().compile_identity().to_string(),
    }
}
