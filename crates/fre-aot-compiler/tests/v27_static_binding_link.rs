#![cfg(all(target_arch = "aarch64", any(target_os = "linux", target_os = "macos")))]

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
#[cfg(target_os = "linux")]
use fre_aot_compiler::{
    LinuxAarch64SearchCompilePolicyV1, build_linux_aarch64_search_v27_exists_object_v1,
    build_linux_aarch64_search_v27_exists_static_binding_v1,
    build_linux_aarch64_search_v27_selected_end_object_v1,
    build_linux_aarch64_search_v27_selected_end_static_binding_v1,
};
use fre_aot_compiler::{SearchAotRuntimeAuthorityV1, SearchV27StaticBindingV1};
#[cfg(target_os = "macos")]
use fre_aot_compiler::{
    SearchCompilePolicyV1, build_macos_aarch64_search_v27_exists_object_v1,
    build_macos_aarch64_search_v27_exists_static_binding_v1,
    build_macos_aarch64_search_v27_selected_end_object_v1,
    build_macos_aarch64_search_v27_selected_end_static_binding_v1,
};

const LITERALS: &[&[u8]] = &[
    b"a",
    b"aaaaaaaaa",
    b"abcabcabc",
    b"abcdefghi",
    b"abcdefghijklmnopqrstuvwxyz012345",
];
static UNIQUE: AtomicU64 = AtomicU64::new(0);

struct PrivateDirectory(PathBuf);

impl PrivateDirectory {
    fn new() -> Self {
        let serial = UNIQUE.fetch_add(1, Ordering::Relaxed);
        let path = std::env::temp_dir().join(format!(
            "fre-aot-compiler-v27-static-binding-link-{}-{serial}",
            std::process::id()
        ));
        DirBuilder::new()
            .mode(0o700)
            .create(&path)
            .expect("private V27 static-binding integration directory");
        Self(std::fs::canonicalize(path).expect("canonical integration directory"))
    }

    fn path(&self) -> &Path {
        &self.0
    }
}

impl Drop for PrivateDirectory {
    fn drop(&mut self) {
        std::fs::remove_dir_all(&self.0).expect("remove private V27 static-binding directory");
    }
}

fn write_new(path: &Path, bytes: &[u8]) {
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(path)
        .expect("create new V27 static-binding fixture");
    file.write_all(bytes)
        .expect("write V27 static-binding fixture");
    file.sync_all().expect("sync V27 static-binding fixture");
}

fn build_artifacts(
    literal: &[u8],
) -> (
    Vec<u8>,
    SearchV27StaticBindingV1,
    Vec<u8>,
    SearchV27StaticBindingV1,
) {
    #[cfg(target_os = "macos")]
    {
        let exists = build_macos_aarch64_search_v27_exists_object_v1(
            literal.to_vec(),
            RustProfile::default(),
            SearchCompilePolicyV1::default(),
        )
        .expect("macOS tag40 Exists object");
        let selected_end = build_macos_aarch64_search_v27_selected_end_object_v1(
            literal.to_vec(),
            RustProfile::default(),
            SearchCompilePolicyV1::default(),
        )
        .expect("macOS tag40 SelectedEnd object");
        let exists_binding = build_macos_aarch64_search_v27_exists_static_binding_v1(&exists)
            .expect("macOS tag40 Exists static binding");
        let selected_end_binding =
            build_macos_aarch64_search_v27_selected_end_static_binding_v1(&selected_end)
                .expect("macOS tag40 SelectedEnd static binding");
        (
            exists.object().as_bytes().to_vec(),
            exists_binding,
            selected_end.object().as_bytes().to_vec(),
            selected_end_binding,
        )
    }
    #[cfg(target_os = "linux")]
    {
        let exists = build_linux_aarch64_search_v27_exists_object_v1(
            literal.to_vec(),
            RustProfile::default(),
            LinuxAarch64SearchCompilePolicyV1::default(),
        )
        .expect("Linux tag40 Exists object");
        let selected_end = build_linux_aarch64_search_v27_selected_end_object_v1(
            literal.to_vec(),
            RustProfile::default(),
            LinuxAarch64SearchCompilePolicyV1::default(),
        )
        .expect("Linux tag40 SelectedEnd object");
        let exists_binding = build_linux_aarch64_search_v27_exists_static_binding_v1(&exists)
            .expect("Linux tag40 Exists static binding");
        let selected_end_binding =
            build_linux_aarch64_search_v27_selected_end_static_binding_v1(&selected_end)
                .expect("Linux tag40 SelectedEnd static binding");
        (
            exists.object().as_bytes().to_vec(),
            exists_binding,
            selected_end.object().as_bytes().to_vec(),
            selected_end_binding,
        )
    }
}

fn link_and_execute(literal: &[u8]) {
    let literal_text = std::str::from_utf8(literal).expect("ASCII integration literal");
    let (exists_object, exists_binding, selected_end_object, selected_end_binding) =
        build_artifacts(literal);
    assert_eq!(
        exists_binding.runtime_authority(),
        SearchAotRuntimeAuthorityV1::Absent
    );
    assert_eq!(
        selected_end_binding.runtime_authority(),
        SearchAotRuntimeAuthorityV1::Absent
    );
    exists_binding.validate().expect("valid Exists binding");
    selected_end_binding
        .validate()
        .expect("valid SelectedEnd binding");

    let directory = PrivateDirectory::new();
    let exists_object_path = directory.path().join("search_v27_exists.o");
    let exists_glue_path = directory.path().join("search_v27_exists_glue.o");
    let exists_header_path = directory.path().join("search_v27_exists.h");
    let selected_end_object_path = directory.path().join("search_v27_selected_end.o");
    let selected_end_glue_path = directory.path().join("search_v27_selected_end_glue.o");
    let selected_end_header_path = directory.path().join("search_v27_selected_end.h");
    let driver_path = directory.path().join("search_v27_static_driver.c");
    let driver_object_path = directory.path().join("search_v27_static_driver.o");
    let executable_path = directory.path().join("search_v27_static_driver");
    write_new(&exists_object_path, &exists_object);
    write_new(&exists_glue_path, exists_binding.glue_object());
    write_new(&exists_header_path, exists_binding.c_header().as_bytes());
    write_new(&selected_end_object_path, &selected_end_object);
    write_new(&selected_end_glue_path, selected_end_binding.glue_object());
    write_new(
        &selected_end_header_path,
        selected_end_binding.c_header().as_bytes(),
    );

    let exists_symbols = exists_binding.symbols();
    let selected_end_symbols = selected_end_binding.symbols();
    let match_end = 2 + literal.len();
    let mut driver = String::new();
    writeln!(
        driver,
        r#"#include "search_v27_exists.h"
#include "search_v27_selected_end.h"

#include <stdint.h>

int main(void) {{
    static const uint8_t haystack[] = "xx{literal_text}yy";
    const uint64_t bytes = (uint64_t)(sizeof(haystack) - 1u);
    const uint64_t poison_start = UINT64_C(0x1122334455667788);
    const uint64_t poison_end = UINT64_C(0x8877665544332211);

    struct {} exists = {{poison_start, poison_end}};
    uint64_t status = {}(haystack, bytes, 0u, bytes, &exists);
    if (status != 1u ||
        exists.untouched_start != poison_start ||
        exists.untouched_end != poison_end) {{
        return 90;
    }}
    status = {}(haystack, bytes, bytes - 1u, bytes, &exists);
    if (status != 0u ||
        exists.untouched_start != poison_start ||
        exists.untouched_end != poison_end) {{
        return 91;
    }}

    struct {} selected_end = {{poison_start, poison_end}};
    status = {}(haystack, bytes, 0u, bytes, &selected_end);
    if (status != 1u ||
        selected_end.untouched_start != poison_start ||
        selected_end.end != {match_end}u) {{
        return 92;
    }}
    selected_end.end = poison_end;
    status = {}(haystack, bytes, bytes - 1u, bytes, &selected_end);
    if (status != 0u ||
        selected_end.untouched_start != poison_start ||
        selected_end.end != poison_end) {{
        return 93;
    }}
    return 0;
}}"#,
        exists_symbols.result_type(),
        exists_symbols.wrapper(),
        exists_symbols.wrapper(),
        selected_end_symbols.result_type(),
        selected_end_symbols.wrapper(),
        selected_end_symbols.wrapper(),
    )
    .expect("render V27 static-binding driver");
    write_new(&driver_path, driver.as_bytes());

    #[cfg(target_os = "macos")]
    let compiler = "/usr/bin/clang";
    #[cfg(target_os = "linux")]
    let compiler = "cc";
    let mut compile = Command::new(compiler);
    #[cfg(target_os = "macos")]
    compile.args(["-arch", "arm64"]);
    let compile = compile
        .args(["-std=c11", "-Wall", "-Wextra", "-Werror"])
        .arg("-I")
        .arg(directory.path())
        .arg(&driver_path)
        .arg("-c")
        .arg("-o")
        .arg(&driver_object_path)
        .output()
        .expect("compile V27 static-binding driver");
    assert!(
        compile.status.success(),
        "C compiler rejected V27 static-binding driver for {literal_text}: {}",
        String::from_utf8_lossy(&compile.stderr)
    );

    let mut link = Command::new(compiler);
    #[cfg(target_os = "macos")]
    link.args(["-arch", "arm64"]);
    let link = link
        .arg(&driver_object_path)
        .arg(&exists_glue_path)
        .arg(&exists_object_path)
        .arg(&selected_end_glue_path)
        .arg(&selected_end_object_path);
    #[cfg(target_os = "macos")]
    let link = link.arg("-Wl,-fatal_warnings");
    #[cfg(target_os = "linux")]
    let link = link
        .arg("-Wl,--fatal-warnings")
        .arg("-Wl,-z,separate-code")
        .arg("-Wl,-z,noexecstack");
    let link = link
        .arg("-o")
        .arg(&executable_path)
        .output()
        .expect("link V27 static-binding objects");
    assert!(
        link.status.success(),
        "linker rejected V27 static-binding objects for {literal_text}: {}",
        String::from_utf8_lossy(&link.stderr)
    );
    let execution = Command::new(&executable_path)
        .output()
        .expect("execute linked V27 static bindings");
    assert!(
        execution.status.success(),
        "linked V27 static bindings failed for {literal_text}: status={:?} stderr={}",
        execution.status.code(),
        String::from_utf8_lossy(&execution.stderr)
    );
}

#[test]
fn v27_output_specific_static_bindings_link_and_execute_across_topologies() {
    for literal in LITERALS {
        link_and_execute(literal);
    }
}
