#![cfg(all(target_os = "linux", target_arch = "aarch64"))]

use std::{
    fmt::Write as _,
    fs::{DirBuilder, OpenOptions},
    io::Write as _,
    os::unix::fs::DirBuilderExt as _,
    path::{Path, PathBuf},
    process::Command,
    sync::atomic::{AtomicU64, Ordering},
};

use fre::RustProfile;
use fre_aot_compiler::{
    LinuxAarch64ExactSearchManifestV1, LinuxAarch64SearchCompilePolicyV1,
    SearchAotRuntimeAuthorityV1, plan_and_compile_linux_aarch64_exact_search_v1,
};
use fre_aot_elf::{BuiltSearchObjectV1, ObjectLimitsV1};
use fre_jit_aarch64::{
    AotLimits, BackendVersion, EmitLimits, SearchBackendPolicy, emit_with_backend,
};
use fre_kernel_ir::{AnchorFlags, Span, ValidateLimits, build_exact_literal};

const LITERAL: &[u8] = b"policy-receipt-26";
static UNIQUE: AtomicU64 = AtomicU64::new(0);

struct PrivateDirectory(PathBuf);

impl PrivateDirectory {
    fn new() -> Self {
        let serial = UNIQUE.fetch_add(1, Ordering::Relaxed);
        let path = std::env::temp_dir().join(format!(
            "fre-aot-compiler-v26-linux-link-{}-{serial}",
            std::process::id()
        ));
        DirBuilder::new()
            .mode(0o700)
            .create(&path)
            .expect("private V26 ELF integration directory");
        Self(std::fs::canonicalize(path).expect("canonical integration directory"))
    }

    fn path(&self) -> &Path {
        &self.0
    }
}

fn write_new(path: &Path, bytes: &[u8]) {
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(path)
        .expect("create new V26 ELF fixture");
    file.write_all(bytes).expect("write V26 ELF fixture");
    file.sync_all().expect("sync V26 ELF fixture");
}

fn generated_header(object: &BuiltSearchObjectV1) -> String {
    let symbols = object.exported_symbols();
    let mut header = fre_aot_elf::C_HEADER_V1.to_owned();
    symbols
        .write_c_declarations(&mut header)
        .expect("render identity-specific V26 declarations");
    writeln!(header, "#define FRE_AOT_SELECTED_ENTRY {}", symbols.entry())
        .expect("render V26 entry alias");
    writeln!(
        header,
        "#define FRE_AOT_SELECTED_METADATA {}",
        symbols.metadata()
    )
    .expect("render V26 metadata alias");
    header
}

fn assert_policy16_aot() {
    let program =
        build_exact_literal::<Span>(LITERAL, AnchorFlags::default(), ValidateLimits::default())
            .expect("V26 exact-literal KIR");
    let image = emit_with_backend(
        &program,
        SearchBackendPolicy::AsimdV26,
        EmitLimits::default(),
    )
    .expect("V26 audited native image");
    let artifact = image
        .to_aot(AotLimits::default())
        .expect("V26 core AOT serialization");
    let bytes = artifact.as_bytes();
    assert_eq!(&bytes[..8], b"FREA64\0\x27");
    assert_eq!(u16::from_le_bytes(bytes[8..10].try_into().unwrap()), 39);
    assert_eq!(u16::from_le_bytes(bytes[66..68].try_into().unwrap()), 16);
}

#[test]
fn v26_tag39_elf_compiler_object_links_and_executes_but_remains_inert() {
    let manifest = LinuxAarch64ExactSearchManifestV1::<Span>::v26_candidate(
        LinuxAarch64SearchCompilePolicyV1::default(),
    )
    .expect("V26 Linux candidate manifest");
    let compiled = plan_and_compile_linux_aarch64_exact_search_v1(
        manifest,
        LITERAL.to_vec(),
        RustProfile::default(),
    )
    .expect("V26 Linux compiler object");
    assert_eq!(
        compiled.runtime_authority(),
        SearchAotRuntimeAuthorityV1::Absent
    );
    assert_eq!(
        compiled.receipt().runtime_authority(),
        SearchAotRuntimeAuthorityV1::Absent
    );
    assert_eq!(
        compiled.receipt().metadata().backend_version(),
        BackendVersion::SEARCH_V26.0
    );
    let receipt_bytes = compiled
        .receipt()
        .canonical_receipt_bytes()
        .expect("canonical V26 Linux receipt");
    let reopened = compiled
        .receipt()
        .validate_canonical_receipt_bytes(&receipt_bytes)
        .expect("strictly reopen V26 Linux receipt");
    reopened
        .validate_object(compiled.object().as_bytes(), ObjectLimitsV1::default())
        .expect("V26 receipt strictly reopens its ELF object");
    assert_policy16_aot();

    let directory = PrivateDirectory::new();
    let object_path = directory.path().join("search_v26.o");
    let header_path = directory.path().join("fre_aot_search_v26.h");
    let driver_path = directory.path().join("search_v26_driver.c");
    let driver_object_path = directory.path().join("search_v26_driver.o");
    let executable_path = directory.path().join("search_v26_driver");
    write_new(&object_path, compiled.object().as_bytes());
    write_new(&header_path, generated_header(compiled.object()).as_bytes());
    write_new(
        &driver_path,
        br#"#include "fre_aot_search_v26.h"

int main(void) {
    static const uint8_t haystack[] = "xxpolicy-receipt-26yy";
    struct fre_aot_search_result_v1 result = {UINT64_MAX, UINT64_MAX};
    uint64_t status = FRE_AOT_SELECTED_ENTRY(
        haystack, sizeof(haystack) - 1u, 0u, sizeof(haystack) - 1u, &result);
    if (status != 1u || result.start != 2u || result.end != 19u) {
        return 68;
    }
    if (FRE_AOT_SELECTED_METADATA.magic[0] != 'F' ||
        FRE_AOT_SELECTED_METADATA.magic[7] != 1u ||
        FRE_AOT_SELECTED_METADATA.backend_version != UINT16_C(39) ||
        FRE_AOT_SELECTED_METADATA.abi_kind != 1u) {
        return 69;
    }
    return 0;
}
"#,
    );
    let compile = Command::new("cc")
        .args(["-std=c11", "-Wall", "-Wextra", "-Werror"])
        .arg("-I")
        .arg(directory.path())
        .arg(&driver_path)
        .arg("-c")
        .arg("-o")
        .arg(&driver_object_path)
        .output()
        .expect("compile V26 ELF driver");
    assert!(
        compile.status.success(),
        "C compiler rejected V26 ELF driver: {}",
        String::from_utf8_lossy(&compile.stderr)
    );
    let link = Command::new("cc")
        .arg(&driver_object_path)
        .arg(&object_path)
        .arg("-Wl,--fatal-warnings")
        .arg("-Wl,-z,separate-code")
        .arg("-Wl,-z,noexecstack")
        .arg("-o")
        .arg(&executable_path)
        .output()
        .expect("link V26 ELF driver");
    assert!(
        link.status.success(),
        "linker rejected V26 ELF object: {}",
        String::from_utf8_lossy(&link.stderr)
    );
    let execution = Command::new(&executable_path)
        .output()
        .expect("execute linked V26 ELF object");
    assert!(
        execution.status.success(),
        "linked V26 ELF object failed: status={:?} stderr={}",
        execution.status.code(),
        String::from_utf8_lossy(&execution.stderr)
    );
}
