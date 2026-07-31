#![cfg(all(target_os = "macos", target_arch = "aarch64"))]

use std::{
    fmt::Write as _,
    fs::{DirBuilder, OpenOptions},
    io::Write as _,
    os::unix::fs::DirBuilderExt as _,
    path::{Path, PathBuf},
    process::Command,
    sync::atomic::{AtomicU64, Ordering},
};

use fre_aot_compiler::{
    ClassSuffixAotObjectV1, SearchAotRuntimeAuthorityV1, compile_macos_aarch64_class_suffix_span_v1,
};

const SOURCE: &[u8] = br"[a-c]+Z";
static UNIQUE: AtomicU64 = AtomicU64::new(0);

struct PrivateDirectory(PathBuf);

impl PrivateDirectory {
    fn new() -> Self {
        let serial = UNIQUE.fetch_add(1, Ordering::Relaxed);
        let path = std::env::temp_dir().join(format!(
            "fre-aot-class-suffix-macos-link-{}-{serial}",
            std::process::id()
        ));
        DirBuilder::new()
            .mode(0o700)
            .create(&path)
            .expect("private class-suffix Mach-O integration directory");
        Self(std::fs::canonicalize(path).expect("canonical integration directory"))
    }

    fn path(&self) -> &Path {
        &self.0
    }
}

impl Drop for PrivateDirectory {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

fn write_new(path: &Path, bytes: &[u8]) {
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(path)
        .expect("create new class-suffix Mach-O fixture");
    file.write_all(bytes)
        .expect("write class-suffix Mach-O fixture");
    file.sync_all().expect("sync class-suffix Mach-O fixture");
}

fn generated_header(object: &ClassSuffixAotObjectV1) -> String {
    let mut header = object.c_header().to_owned();
    match object {
        ClassSuffixAotObjectV1::Macos(object) => object
            .exported_symbols()
            .write_c_declarations(&mut header)
            .expect("render class-suffix Mach-O declarations"),
        ClassSuffixAotObjectV1::Linux(_) => panic!("expected Mach-O object"),
    }
    writeln!(
        header,
        "#define FRE_AOT_SELECTED_ENTRY {}",
        object.entry_symbol()
    )
    .expect("render class-suffix entry alias");
    writeln!(
        header,
        "#define FRE_AOT_SELECTED_METADATA {}",
        object.metadata_symbol()
    )
    .expect("render class-suffix metadata alias");
    header
}

#[test]
fn class_suffix_macho_links_and_executes_greedy_windowed_search_but_remains_inert() {
    let compiled = compile_macos_aarch64_class_suffix_span_v1(SOURCE.to_vec())
        .expect("class-suffix Mach-O compiler object");
    assert_eq!(
        compiled.runtime_authority(),
        SearchAotRuntimeAuthorityV1::Absent
    );
    compiled
        .validate_against_source(SOURCE)
        .expect("source-bound independent class-suffix validation");

    let directory = PrivateDirectory::new();
    let object_path = directory.path().join("class_suffix.o");
    let header_path = directory.path().join("fre_aot_class_suffix.h");
    let driver_path = directory.path().join("class_suffix_driver.c");
    let driver_object_path = directory.path().join("class_suffix_driver.o");
    let executable_path = directory.path().join("class_suffix_driver");
    write_new(&object_path, compiled.object().as_bytes());
    write_new(&header_path, generated_header(compiled.object()).as_bytes());
    write_new(
        &driver_path,
        br#"#include "fre_aot_class_suffix.h"

static const uint8_t haystack[] = "--abccZ--aZ--abcQ--cZ";
static const size_t poison_start = (size_t)UINT64_C(0xa5a5a5a5a5a5a5a5);
static const size_t poison_end = (size_t)UINT64_C(0x5a5a5a5a5a5a5a5a);

static int check_match(size_t window_start, size_t window_end,
                       size_t expected_start, size_t expected_end) {
    struct fre_aot_search_result_v1 result = {poison_start, poison_end};
    uint64_t status = FRE_AOT_SELECTED_ENTRY(
        haystack, sizeof(haystack) - 1u, window_start, window_end, &result);
    return status == 1u && result.start == expected_start &&
           result.end == expected_end;
}

static int check_no_match(size_t window_start, size_t window_end) {
    struct fre_aot_search_result_v1 result = {poison_start, poison_end};
    uint64_t status = FRE_AOT_SELECTED_ENTRY(
        haystack, sizeof(haystack) - 1u, window_start, window_end, &result);
    return status == 0u && result.start == poison_start &&
           result.end == poison_end;
}

int main(void) {
    if (!check_match(0u, 21u, 2u, 7u) ||
        !check_match(3u, 21u, 3u, 7u) ||
        !check_match(4u, 7u, 4u, 7u) ||
        !check_match(5u, 7u, 5u, 7u) ||
        !check_match(7u, 11u, 9u, 11u) ||
        !check_match(19u, 21u, 19u, 21u) ||
        !check_no_match(2u, 6u) ||
        !check_no_match(7u, 10u) ||
        !check_no_match(21u, 21u)) {
        return 70;
    }
    if (FRE_AOT_SELECTED_METADATA.magic[0] != 'F' ||
        FRE_AOT_SELECTED_METADATA.magic[7] != 1u ||
        FRE_AOT_SELECTED_METADATA.backend_version != UINT16_C(8) ||
        FRE_AOT_SELECTED_METADATA.abi_kind != FRE_AOT_ABI_SEARCH_V1 ||
        FRE_AOT_SELECTED_METADATA.literal_bytes != 1u ||
        FRE_AOT_SELECTED_METADATA.rodata_bytes != 33u) {
        return 71;
    }
    return 0;
}
"#,
    );
    let compile = Command::new("/usr/bin/clang")
        .args(["-arch", "arm64", "-std=c11", "-Wall", "-Wextra", "-Werror"])
        .arg("-I")
        .arg(directory.path())
        .arg(&driver_path)
        .arg("-c")
        .arg("-o")
        .arg(&driver_object_path)
        .output()
        .expect("compile class-suffix Mach-O driver");
    assert!(
        compile.status.success(),
        "clang rejected class-suffix Mach-O driver: {}",
        String::from_utf8_lossy(&compile.stderr)
    );
    let link = Command::new("/usr/bin/clang")
        .args(["-arch", "arm64"])
        .arg(&driver_object_path)
        .arg(&object_path)
        .arg("-Wl,-fatal_warnings")
        .arg("-Wl,-segprot,__TEXT,rx,rx")
        .arg("-Wl,-segprot,__FRE_CONST,r,r")
        .arg("-o")
        .arg(&executable_path)
        .output()
        .expect("link class-suffix Mach-O driver");
    assert!(
        link.status.success(),
        "clang rejected class-suffix Mach-O object: {}",
        String::from_utf8_lossy(&link.stderr)
    );
    let execution = Command::new(&executable_path)
        .output()
        .expect("execute linked class-suffix Mach-O object");
    assert!(
        execution.status.success(),
        "linked class-suffix Mach-O object failed: status={:?} stderr={}",
        execution.status.code(),
        String::from_utf8_lossy(&execution.stderr)
    );
}
