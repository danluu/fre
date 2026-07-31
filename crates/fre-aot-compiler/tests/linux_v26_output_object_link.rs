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
    LinuxAarch64SearchCompilePolicyV1, SearchAotRuntimeAuthorityV1,
    build_linux_aarch64_search_v26_exists_object_v1,
    build_linux_aarch64_search_v26_selected_end_object_v1,
};
use fre_aot_elf::BuiltSearchObjectV1;
use fre_kernel_ir::OutputKind;

const LITERAL: &[u8] = b"abcdefghi";
static UNIQUE: AtomicU64 = AtomicU64::new(0);

struct PrivateDirectory(PathBuf);

impl PrivateDirectory {
    fn new() -> Self {
        let serial = UNIQUE.fetch_add(1, Ordering::Relaxed);
        let path = std::env::temp_dir().join(format!(
            "fre-aot-compiler-v26-output-link-{}-{serial}",
            std::process::id()
        ));
        DirBuilder::new()
            .mode(0o700)
            .create(&path)
            .expect("private V26 output-object integration directory");
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
        .expect("create new V26 output-object fixture");
    file.write_all(bytes)
        .expect("write V26 output-object fixture");
    file.sync_all().expect("sync V26 output-object fixture");
}

fn output_specific_header(
    exists: &BuiltSearchObjectV1,
    selected_end: &BuiltSearchObjectV1,
) -> String {
    let exists_symbols = exists.exported_symbols();
    let selected_end_symbols = selected_end.exported_symbols();
    let mut header = String::from(
        "#ifndef FRE_V26_OUTPUT_OBJECT_SMOKE_H\n\
         #define FRE_V26_OUTPUT_OBJECT_SMOKE_H\n\
         #include <stdint.h>\n\
         struct fre_v26_exists_result_v1 {\n\
           uint64_t untouched_start;\n\
           uint64_t untouched_end;\n\
         };\n\
         struct fre_v26_selected_end_result_v1 {\n\
           uint64_t untouched_start;\n\
           uint64_t end;\n\
         };\n",
    );
    writeln!(
        header,
        "extern uint64_t {}(const uint8_t *, uint64_t, uint64_t, uint64_t, struct fre_v26_exists_result_v1 *);",
        exists_symbols.entry()
    )
    .expect("render Exists entry declaration");
    writeln!(
        header,
        "extern uint64_t {}(const uint8_t *, uint64_t, uint64_t, uint64_t, struct fre_v26_selected_end_result_v1 *);",
        selected_end_symbols.entry()
    )
    .expect("render SelectedEnd entry declaration");
    writeln!(
        header,
        "#define FRE_V26_EXISTS_ENTRY {}",
        exists_symbols.entry()
    )
    .expect("render Exists entry alias");
    writeln!(
        header,
        "#define FRE_V26_SELECTED_END_ENTRY {}",
        selected_end_symbols.entry()
    )
    .expect("render SelectedEnd entry alias");
    header.push_str("#endif\n");
    header
}

#[test]
fn v26_exists_and_selected_end_elf_objects_link_execute_and_remain_inert() {
    let exists = build_linux_aarch64_search_v26_exists_object_v1(
        LITERAL.to_vec(),
        RustProfile::default(),
        LinuxAarch64SearchCompilePolicyV1::default(),
    )
    .expect("Linux V26 Exists object");
    let selected_end = build_linux_aarch64_search_v26_selected_end_object_v1(
        LITERAL.to_vec(),
        RustProfile::default(),
        LinuxAarch64SearchCompilePolicyV1::default(),
    )
    .expect("Linux V26 SelectedEnd object");
    assert_eq!(exists.receipt().output(), OutputKind::Exists);
    assert_eq!(selected_end.receipt().output(), OutputKind::SelectedEnd);
    assert_eq!(
        exists.runtime_authority(),
        SearchAotRuntimeAuthorityV1::Absent
    );
    assert_eq!(
        selected_end.runtime_authority(),
        SearchAotRuntimeAuthorityV1::Absent
    );

    let directory = PrivateDirectory::new();
    let exists_path = directory.path().join("search_v26_exists.o");
    let selected_end_path = directory.path().join("search_v26_selected_end.o");
    let header_path = directory.path().join("fre_v26_output_object_smoke.h");
    let driver_path = directory.path().join("search_v26_output_driver.c");
    let driver_object_path = directory.path().join("search_v26_output_driver.o");
    let executable_path = directory.path().join("search_v26_output_driver");
    write_new(&exists_path, exists.object().as_bytes());
    write_new(&selected_end_path, selected_end.object().as_bytes());
    write_new(
        &header_path,
        output_specific_header(exists.object(), selected_end.object()).as_bytes(),
    );
    write_new(
        &driver_path,
        br#"#include "fre_v26_output_object_smoke.h"

#include <stdint.h>

int main(void) {
    static const uint8_t haystack[] = "xxabcdefghiyy";
    const uint64_t bytes = (uint64_t)(sizeof(haystack) - 1u);
    const uint64_t poison_start = UINT64_C(0x1122334455667788);
    const uint64_t poison_end = UINT64_C(0x8877665544332211);

    struct fre_v26_exists_result_v1 exists = {poison_start, poison_end};
    uint64_t status = FRE_V26_EXISTS_ENTRY(haystack, bytes, 0u, bytes, &exists);
    if (status != 1u ||
        exists.untouched_start != poison_start ||
        exists.untouched_end != poison_end) {
        return 80;
    }
    exists.untouched_start = poison_start;
    exists.untouched_end = poison_end;
    status = FRE_V26_EXISTS_ENTRY(haystack, bytes, 12u, bytes, &exists);
    if (status != 0u ||
        exists.untouched_start != poison_start ||
        exists.untouched_end != poison_end) {
        return 81;
    }

    struct fre_v26_selected_end_result_v1 selected_end = {
        poison_start,
        poison_end
    };
    status = FRE_V26_SELECTED_END_ENTRY(
        haystack, bytes, 0u, bytes, &selected_end);
    if (status != 1u ||
        selected_end.untouched_start != poison_start ||
        selected_end.end != 11u) {
        return 82;
    }
    selected_end.untouched_start = poison_start;
    selected_end.end = poison_end;
    status = FRE_V26_SELECTED_END_ENTRY(
        haystack, bytes, 12u, bytes, &selected_end);
    if (status != 0u ||
        selected_end.untouched_start != poison_start ||
        selected_end.end != poison_end) {
        return 83;
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
        .expect("compile V26 output-object driver");
    assert!(
        compile.status.success(),
        "C compiler rejected V26 output-object driver: {}",
        String::from_utf8_lossy(&compile.stderr)
    );
    let link = Command::new("cc")
        .arg(&driver_object_path)
        .arg(&exists_path)
        .arg(&selected_end_path)
        .arg("-Wl,--fatal-warnings")
        .arg("-Wl,-z,separate-code")
        .arg("-Wl,-z,noexecstack")
        .arg("-o")
        .arg(&executable_path)
        .output()
        .expect("link V26 output objects");
    assert!(
        link.status.success(),
        "linker rejected V26 output objects: {}",
        String::from_utf8_lossy(&link.stderr)
    );
    let execution = Command::new(&executable_path)
        .output()
        .expect("execute linked V26 output objects");
    assert!(
        execution.status.success(),
        "linked V26 output objects failed: status={:?} stderr={}",
        execution.status.code(),
        String::from_utf8_lossy(&execution.stderr)
    );
}
