#![cfg(all(target_os = "macos", target_arch = "aarch64"))]

use std::{
    fmt::Write as FmtWrite,
    fs::{DirBuilder, OpenOptions},
    io::Write as IoWrite,
    os::unix::fs::DirBuilderExt,
    path::{Path, PathBuf},
    process::Command,
    sync::atomic::{AtomicU64, Ordering},
};

use fre_aot_aarch64::{CountEmitLimitsV2, emit_count_v2};
use fre_aot_macho::{
    BindingIdentity, BuiltCountObjectV2, BuiltObject, C_HEADER, METADATA_BYTES_V1,
    METADATA_BYTES_V2, ObjectLimits, emit_aggregate_object, emit_count_object_v2,
    emit_search_object, inspect_count_object_v2, inspect_object, validate_count_object_v2,
};
use fre_jit_aarch64::{
    BackendVersion, EmitLimits, SearchBackendPolicy, emit_exact_aggregate, emit_with_backend,
};
use fre_kernel_ir::{
    AnchorFlags, Count, Span, ValidateLimits, build_exact_aggregate, build_exact_literal,
};

static UNIQUE: AtomicU64 = AtomicU64::new(0);

struct PrivateDirectory(PathBuf);

impl PrivateDirectory {
    fn new() -> Self {
        let serial = UNIQUE.fetch_add(1, Ordering::Relaxed);
        let path =
            std::env::temp_dir().join(format!("fre-aot-macho-{}-{serial}", std::process::id()));
        DirBuilder::new()
            .mode(0o700)
            .create(&path)
            .expect("private integration directory");
        Self(std::fs::canonicalize(path).expect("canonical private integration directory"))
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
        .expect("create new integration fixture");
    file.write_all(bytes).expect("write integration fixture");
    file.sync_all().expect("sync integration fixture");
}

fn generated_header(object: &BuiltObject) -> String {
    let symbols = object.exported_symbols();
    let mut header = C_HEADER.to_owned();
    symbols
        .write_c_declarations(&mut header)
        .expect("render identity-specific declarations");
    header.push_str("#define FRE_AOT_SELECTED_ENTRY ");
    header.push_str(symbols.entry().as_str());
    header.push('\n');
    header.push_str("#define FRE_AOT_SELECTED_PAYLOAD ");
    header.push_str(symbols.payload().as_str());
    header.push('\n');
    header.push_str("#define FRE_AOT_SELECTED_METADATA ");
    header.push_str(symbols.metadata().as_str());
    header.push('\n');
    header
}

fn generated_count_v2_header(object: &BuiltCountObjectV2) -> String {
    let symbols = object.exported_symbols();
    let mut header = C_HEADER.to_owned();
    symbols
        .write_c_declarations(&mut header)
        .expect("render identity-specific Count V2 declarations");
    header.push_str("#define FRE_AOT_SELECTED_ENTRY ");
    header.push_str(symbols.entry().as_str());
    header.push('\n');
    header.push_str("#define FRE_AOT_SELECTED_PAYLOAD ");
    header.push_str(symbols.payload().as_str());
    header.push('\n');
    header.push_str("#define FRE_AOT_SELECTED_METADATA ");
    header.push_str(symbols.metadata().as_str());
    header.push('\n');
    header
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct LinkedSection {
    address: u64,
    size: u64,
    file_offset: u64,
}

fn field<'a>(record: &'a str, name: &str) -> &'a str {
    record
        .lines()
        .find_map(|line| {
            let mut fields = line.split_whitespace();
            (fields.next() == Some(name))
                .then(|| fields.next())
                .flatten()
        })
        .unwrap_or_else(|| panic!("missing {name} in otool record:\n{record}"))
}

fn numeric_field(record: &str, name: &str) -> u64 {
    let value = field(record, name);
    value
        .strip_prefix("0x")
        .map_or_else(|| value.parse::<u64>(), |hex| u64::from_str_radix(hex, 16))
        .unwrap_or_else(|_| panic!("invalid {name} value {value}"))
}

fn segment_record<'a>(otool: &'a str, segment: &str) -> &'a str {
    otool
        .split("Load command ")
        .find(|command| {
            let segment_header = command.split("Section").next().unwrap_or(command);
            segment_header
                .lines()
                .any(|line| line.split_whitespace().eq(["segname", segment]))
        })
        .unwrap_or_else(|| panic!("missing linked segment {segment}"))
}

fn assert_segment_protections(otool: &str, segment: &str, expected: &[&str]) {
    let record = segment_record(otool, segment);
    for protection in ["maxprot", "initprot"] {
        let actual = field(record, protection);
        assert!(
            expected.contains(&actual),
            "{segment} {protection} must be one of {expected:?}, got {actual}"
        );
    }
}

fn linked_section(otool: &str, segment: &str, section: &str) -> LinkedSection {
    let record = otool
        .split("Section")
        .find(|record| {
            record
                .lines()
                .any(|line| line.split_whitespace().eq(["sectname", section]))
                && record
                    .lines()
                    .any(|line| line.split_whitespace().eq(["segname", segment]))
        })
        .unwrap_or_else(|| panic!("missing linked {segment},{section} section"));
    LinkedSection {
        address: numeric_field(record, "addr"),
        size: numeric_field(record, "size"),
        file_offset: numeric_field(record, "offset"),
    }
}

fn linked_symbol_address(nm: &str, symbol: &str) -> u64 {
    let mach_symbol = format!("_{symbol}");
    let line = nm
        .lines()
        .find(|line| line.split_whitespace().last() == Some(mach_symbol.as_str()))
        .unwrap_or_else(|| panic!("missing linked symbol {symbol}"));
    let address = line
        .split_whitespace()
        .next()
        .expect("linked symbol address");
    u64::from_str_radix(address.trim_start_matches("0x"), 16).expect("hex linked symbol address")
}

fn provider_label(link_map: &str, object_path: &Path) -> String {
    let expected_path = object_path.to_string_lossy();
    link_map
        .lines()
        .find_map(|line| {
            let close = line.find(']')?;
            let label = line.get(..=close)?;
            let path = line.get(close.checked_add(1)?..)?.trim();
            (label.starts_with('[') && path == expected_path.as_ref()).then(|| label.to_owned())
        })
        .unwrap_or_else(|| panic!("link map omitted exact input {}", object_path.display()))
}

fn assert_retained_provider(
    link_map: &str,
    object_path: &Path,
    expected_bytes: &[u8],
    symbols: &[&str],
) {
    let retained = std::fs::read(object_path).expect("read retained link input");
    assert_eq!(retained, expected_bytes, "retained object bytes changed");
    let provider = provider_label(link_map, object_path);
    for symbol in symbols {
        let mach_symbol = format!("_{symbol}");
        let definitions: Vec<_> = link_map
            .lines()
            .filter(|line| line.split_whitespace().last() == Some(mach_symbol.as_str()))
            .collect();
        assert_eq!(
            definitions.len(),
            1,
            "link map must contain exactly one definition of {symbol}"
        );
        assert!(
            definitions[0].contains(&provider),
            "{symbol} came from an unexpected provider: {}",
            definitions[0]
        );
    }
}

fn align_up(value: u64, alignment: u64) -> u64 {
    assert!(alignment.is_power_of_two());
    let mask = alignment.checked_sub(1).expect("positive alignment");
    value.checked_add(mask).expect("linked range alignment") & !mask
}

fn assert_exact_section_layout(
    section: LinkedSection,
    ranges: &[(u64, u64)],
    alignment: u64,
    linked_bytes: &[u8],
) {
    let mut ordered = ranges.to_vec();
    ordered.sort_unstable_by_key(|&(address, _)| address);
    assert!(!ordered.is_empty());
    assert_eq!(ordered[0].0, section.address);
    let mut cursor = section.address;
    for &(address, bytes) in &ordered {
        let expected_address = align_up(cursor, alignment);
        assert_eq!(address, expected_address, "unexpected linked section gap");
        let gap_start = section
            .file_offset
            .checked_add(
                cursor
                    .checked_sub(section.address)
                    .expect("gap starts inside section"),
            )
            .expect("gap file offset");
        let gap_end = section
            .file_offset
            .checked_add(
                address
                    .checked_sub(section.address)
                    .expect("gap ends inside section"),
            )
            .expect("gap file end");
        let gap = linked_bytes
            .get(
                usize::try_from(gap_start).expect("gap offset fits usize")
                    ..usize::try_from(gap_end).expect("gap end fits usize"),
            )
            .expect("linked alignment gap");
        assert!(gap.iter().all(|&byte| byte == 0));
        cursor = address.checked_add(bytes).expect("linked range end");
    }
    assert_eq!(
        cursor,
        section
            .address
            .checked_add(section.size)
            .expect("linked section end"),
        "linked section contains unaccounted content"
    );
}

fn assert_linked_bytes(section: LinkedSection, address: u64, expected: &[u8], linked_bytes: &[u8]) {
    let relative = address
        .checked_sub(section.address)
        .expect("symbol must start inside section");
    let start = section
        .file_offset
        .checked_add(relative)
        .expect("linked byte offset");
    let end = start
        .checked_add(u64::try_from(expected.len()).expect("expected length fits u64"))
        .expect("linked byte end");
    assert_eq!(
        linked_bytes
            .get(
                usize::try_from(start).expect("linked offset fits usize")
                    ..usize::try_from(end).expect("linked end fits usize"),
            )
            .expect("linked byte range"),
        expected
    );
}

#[test]
fn apple_tools_link_and_execute_inert_search_v12_object() {
    let program =
        build_exact_literal::<Span>(b"needle", AnchorFlags::default(), ValidateLimits::default())
            .expect("Search V12 program");
    let image = emit_with_backend(
        &program,
        SearchBackendPolicy::AsimdV12,
        EmitLimits::default(),
    )
    .expect("Search V12 image");
    let object = emit_search_object(
        &image,
        BindingIdentity::new([0x25; 32]).expect("nonzero test binding"),
        ObjectLimits::default(),
    )
    .expect("Search V12 Mach-O object");
    let inspection =
        inspect_object(object.as_bytes(), ObjectLimits::default()).expect("inspect V12 object");
    assert_eq!(
        inspection.metadata().backend_version(),
        BackendVersion::SEARCH_V12.0
    );

    let directory = PrivateDirectory::new();
    let object_path = directory.path().join("search_v12.o");
    let header_path = directory.path().join("fre_aot_search_v12.h");
    let driver_path = directory.path().join("search_v12_driver.c");
    let driver_object_path = directory.path().join("search_v12_driver.o");
    let executable_path = directory.path().join("search_v12_driver");
    write_new(&object_path, object.as_bytes());
    write_new(&header_path, generated_header(&object).as_bytes());
    write_new(
        &driver_path,
        br#"#include "fre_aot_search_v12.h"

int main(void) {
    static const uint8_t haystack[] = "xxneedleyy";
    struct fre_aot_search_result_v1 result = {UINT64_MAX, UINT64_MAX};
    uint64_t status = FRE_AOT_SELECTED_ENTRY(
        haystack, sizeof(haystack) - 1u, 0u, sizeof(haystack) - 1u, &result);
    if (status != 1u || result.start != 2u || result.end != 8u) {
        return 40;
    }
    if (FRE_AOT_SELECTED_METADATA.backend_version != UINT16_C(25) ||
        FRE_AOT_SELECTED_METADATA.abi_kind != FRE_AOT_ABI_SEARCH_V1) {
        return 41;
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
        .expect("compile Search V12 driver");
    assert!(
        compile.status.success(),
        "clang rejected Search V12 driver: {}",
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
        .expect("link Search V12 driver");
    assert!(
        link.status.success(),
        "clang rejected Search V12 object: {}",
        String::from_utf8_lossy(&link.stderr)
    );
    let execution = Command::new(&executable_path)
        .output()
        .expect("execute linked Search V12 object");
    assert!(
        execution.status.success(),
        "linked Search V12 failed: status={:?} stderr={}",
        execution.status.code(),
        String::from_utf8_lossy(&execution.stderr)
    );
}

#[test]
#[allow(
    clippy::too_many_lines,
    reason = "one native integration transaction proves object, link-map, protection, and ABI invariants"
)]
fn apple_tools_recognize_link_and_execute_aggregate_object() {
    let program =
        build_exact_aggregate::<Count>(b"aba", ValidateLimits::default()).expect("program");
    let image =
        emit_exact_aggregate(&program, EmitLimits::default()).expect("audited native image");
    let object = emit_aggregate_object(
        &image,
        BindingIdentity::new([0x7c; 32]).unwrap(),
        ObjectLimits::default(),
    )
    .expect("Mach-O object");
    let second_program =
        build_exact_aggregate::<Count>(b"--", ValidateLimits::default()).expect("second program");
    let second_image = emit_exact_aggregate(&second_program, EmitLimits::default())
        .expect("second audited native image");
    let second_object = emit_aggregate_object(
        &second_image,
        BindingIdentity::new([0x6b; 32]).unwrap(),
        ObjectLimits::default(),
    )
    .expect("second Mach-O object");
    assert_ne!(object.exported_symbols(), second_object.exported_symbols(),);

    let directory = PrivateDirectory::new();
    let object_path = directory.path().join("aggregate.o");
    let duplicate_object_path = directory.path().join("aggregate_duplicate.o");
    let second_object_path = directory.path().join("aggregate_two.o");
    let header_path = directory.path().join("fre_aot_macho.h");
    let driver_path = directory.path().join("driver.c");
    let driver_object_path = directory.path().join("driver.o");
    let executable_path = directory.path().join("driver");
    let duplicate_executable_path = directory.path().join("duplicate_driver");
    let map_path = directory.path().join("driver.map");
    write_new(&object_path, object.as_bytes());
    write_new(&duplicate_object_path, object.as_bytes());
    write_new(&second_object_path, second_object.as_bytes());
    let mut aggregate_header = generated_header(&object);
    let second_symbols = second_object.exported_symbols();
    second_symbols
        .write_c_declarations(&mut aggregate_header)
        .expect("render second identity-specific declarations");
    aggregate_header.push_str("#define FRE_AOT_SECOND_ENTRY ");
    aggregate_header.push_str(second_symbols.entry().as_str());
    aggregate_header.push('\n');
    aggregate_header.push_str("#define FRE_AOT_SECOND_PAYLOAD ");
    aggregate_header.push_str(second_symbols.payload().as_str());
    aggregate_header.push('\n');
    aggregate_header.push_str("#define FRE_AOT_SECOND_METADATA ");
    aggregate_header.push_str(second_symbols.metadata().as_str());
    aggregate_header.push('\n');
    write_new(&header_path, aggregate_header.as_bytes());
    write_new(
        &driver_path,
        br#"#include "fre_aot_macho.h"
#include <string.h>

int main(void) {
    static const uint8_t haystack[] = "aba--abaaba";
    static const uint8_t empty_anchor = 0;
    struct fre_aot_aggregate_result_v1 result = {UINT64_C(0xa5a5a5a5a5a5a5a5)};
    uint64_t status = FRE_AOT_SELECTED_ENTRY(
        haystack, sizeof(haystack) - 1u, &result);
    if (status != 0u || result.value != 3u) {
        return 10;
    }
    if (FRE_AOT_SELECTED_METADATA.format_version != FRE_AOT_METADATA_VERSION ||
        FRE_AOT_SELECTED_METADATA.abi_kind != FRE_AOT_ABI_AGGREGATE_V1 ||
        FRE_AOT_SELECTED_METADATA.status_bits != 64u ||
        FRE_AOT_SELECTED_METADATA.abi_schema != 1u ||
        FRE_AOT_SELECTED_METADATA.entry_offset != 0u) {
        return 11;
    }
    if (FRE_AOT_SELECTED_PAYLOAD[0] == 0u &&
        FRE_AOT_SELECTED_METADATA.code_bytes == 0u) {
        return 12;
    }
    struct fre_aot_aggregate_result_v1 second_result = {0};
    uint64_t second_status = FRE_AOT_SECOND_ENTRY(
        haystack, sizeof(haystack) - 1u, &second_result);
    if (second_status != 0u || second_result.value != 1u ||
        memcmp(FRE_AOT_SECOND_METADATA.compile_identity,
               FRE_AOT_SELECTED_METADATA.compile_identity, 32u) == 0) {
        return 13;
    }
    struct fre_aot_aggregate_result_v1 empty_result = {
        UINT64_C(0x5a5a5a5a5a5a5a5a)
    };
    uint64_t empty_status = FRE_AOT_SELECTED_ENTRY(
        &empty_anchor, 0u, &empty_result);
    if (empty_status != 0u || empty_result.value != 0u) {
        return 14;
    }
    return 0;
}

"#,
    );

    let otool = Command::new("/usr/bin/otool")
        .args(["-hv", "-l"])
        .arg(&object_path)
        .output()
        .expect("run otool");
    assert!(
        otool.status.success(),
        "otool rejected object: {}",
        String::from_utf8_lossy(&otool.stderr)
    );
    let otool_stdout = String::from_utf8_lossy(&otool.stdout);
    assert!(otool_stdout.contains("OBJECT"));
    assert_eq!(otool_stdout.matches("Load command ").count(), 4);
    assert_eq!(otool_stdout.matches("sectname __fre_image").count(), 1);
    assert_eq!(otool_stdout.matches("sectname __fre_meta").count(), 1);
    assert_eq!(otool_stdout.matches("segname __FRE_CONST").count(), 1);
    assert_eq!(otool_stdout.matches("nreloc 0").count(), 2);
    assert!(!otool_stdout.contains("LC_LOAD_DYLIB"));
    assert!(!otool_stdout.contains("LC_RPATH"));

    let nm = Command::new("/usr/bin/nm")
        .arg("-g")
        .arg(&object_path)
        .output()
        .expect("run nm");
    assert!(
        nm.status.success(),
        "nm rejected object: {}",
        String::from_utf8_lossy(&nm.stderr)
    );
    let nm_stdout = String::from_utf8_lossy(&nm.stdout);
    let mut actual_symbols: Vec<_> = nm_stdout
        .lines()
        .filter_map(|line| line.split_whitespace().last())
        .filter_map(|symbol| symbol.strip_prefix('_'))
        .collect();
    actual_symbols.sort_unstable();
    let exported = object.exported_symbols();
    let mut expected_symbols = [
        exported.entry().as_str(),
        exported.payload().as_str(),
        exported.metadata().as_str(),
    ];
    expected_symbols.sort_unstable();
    assert_eq!(actual_symbols, expected_symbols);
    assert!(!nm_stdout.lines().any(|line| line.contains(" U ")));
    let symbol_value = |name: &str| {
        nm_stdout
            .lines()
            .find(|line| line.ends_with(name))
            .and_then(|line| line.split_whitespace().next())
            .expect("external symbol value")
            .to_owned()
    };
    assert_eq!(
        symbol_value(exported.entry().as_str()),
        symbol_value(exported.payload().as_str())
    );
    assert_ne!(
        symbol_value(exported.entry().as_str()),
        symbol_value(exported.metadata().as_str())
    );

    let compile_driver = Command::new("/usr/bin/clang")
        .args(["-arch", "arm64", "-std=c11", "-Wall", "-Wextra", "-Werror"])
        .arg("-I")
        .arg(directory.path())
        .arg(&driver_path)
        .arg("-c")
        .arg("-o")
        .arg(&driver_object_path)
        .output()
        .expect("compile aggregate driver");
    assert!(
        compile_driver.status.success(),
        "clang rejected aggregate driver: {}",
        String::from_utf8_lossy(&compile_driver.stderr)
    );
    let link = Command::new("/usr/bin/clang")
        .args(["-arch", "arm64"])
        .arg(&driver_object_path)
        .arg(&object_path)
        .arg(&second_object_path)
        .arg("-Wl,-fatal_warnings")
        .arg("-Wl,-segprot,__TEXT,rx,rx")
        .arg("-Wl,-segprot,__FRE_CONST,r,r")
        .arg(format!("-Wl,-map,{}", map_path.display()))
        .arg("-o")
        .arg(&executable_path)
        .output()
        .expect("run clang driver link");
    assert!(
        link.status.success(),
        "clang rejected object: {}",
        String::from_utf8_lossy(&link.stderr)
    );
    let duplicate_link = Command::new("/usr/bin/clang")
        .args(["-arch", "arm64"])
        .arg(&driver_object_path)
        .arg(&object_path)
        .arg(&duplicate_object_path)
        .arg("-Wl,-fatal_warnings")
        .arg("-o")
        .arg(&duplicate_executable_path)
        .output()
        .expect("run duplicate-provider rejection link");
    assert!(
        !duplicate_link.status.success(),
        "linker accepted duplicate identity-specific definitions"
    );
    let duplicate_stderr = String::from_utf8_lossy(&duplicate_link.stderr);
    assert!(
        duplicate_stderr.contains("duplicate symbol")
            || duplicate_stderr.contains("Undefined symbols"),
        "duplicate-provider failure was not a recognized Darwin linker diagnostic: {duplicate_stderr}"
    );
    let link_map = std::fs::read_to_string(&map_path).expect("retained aggregate link map");
    assert_retained_provider(
        &link_map,
        &object_path,
        object.as_bytes(),
        &[
            exported.entry().as_str(),
            exported.payload().as_str(),
            exported.metadata().as_str(),
        ],
    );
    assert_retained_provider(
        &link_map,
        &second_object_path,
        second_object.as_bytes(),
        &[
            second_symbols.entry().as_str(),
            second_symbols.payload().as_str(),
            second_symbols.metadata().as_str(),
        ],
    );
    let linked_otool = Command::new("/usr/bin/otool")
        .arg("-l")
        .arg(&executable_path)
        .output()
        .expect("inspect linked aggregate protections");
    assert!(linked_otool.status.success());
    let linked_otool_stdout = String::from_utf8_lossy(&linked_otool.stdout);
    assert_eq!(
        linked_otool_stdout.matches("sectname __fre_image").count(),
        1
    );
    assert_eq!(
        linked_otool_stdout.matches("sectname __fre_meta").count(),
        1
    );
    assert_segment_protections(&linked_otool_stdout, "__TEXT", &["0x00000005", "r-x"]);
    assert_segment_protections(&linked_otool_stdout, "__FRE_CONST", &["0x00000001", "r--"]);
    let linked_payload_section = linked_section(&linked_otool_stdout, "__TEXT", "__fre_image");
    let linked_metadata_section = linked_section(&linked_otool_stdout, "__FRE_CONST", "__fre_meta");
    let linked_nm = Command::new("/usr/bin/nm")
        .arg("-n")
        .arg(&executable_path)
        .output()
        .expect("inspect linked aggregate symbols");
    assert!(linked_nm.status.success());
    let linked_nm_stdout = String::from_utf8_lossy(&linked_nm.stdout);
    let payload_address = linked_symbol_address(&linked_nm_stdout, exported.payload().as_str());
    let second_payload_address =
        linked_symbol_address(&linked_nm_stdout, second_symbols.payload().as_str());
    assert_eq!(
        linked_symbol_address(&linked_nm_stdout, exported.entry().as_str()),
        payload_address
    );
    assert_eq!(
        linked_symbol_address(&linked_nm_stdout, second_symbols.entry().as_str()),
        second_payload_address
    );
    let metadata_address = linked_symbol_address(&linked_nm_stdout, exported.metadata().as_str());
    let second_metadata_address =
        linked_symbol_address(&linked_nm_stdout, second_symbols.metadata().as_str());
    let inspected = inspect_object(object.as_bytes(), ObjectLimits::default())
        .expect("inspect retained object");
    let second_inspected = inspect_object(second_object.as_bytes(), ObjectLimits::default())
        .expect("inspect second retained object");
    let linked_bytes = std::fs::read(&executable_path).expect("read linked aggregate image");
    assert_exact_section_layout(
        linked_payload_section,
        &[
            (
                payload_address,
                u64::try_from(inspected.payload().len()).expect("payload size fits u64"),
            ),
            (
                second_payload_address,
                u64::try_from(second_inspected.payload().len())
                    .expect("second payload size fits u64"),
            ),
        ],
        16,
        &linked_bytes,
    );
    assert_exact_section_layout(
        linked_metadata_section,
        &[
            (
                metadata_address,
                u64::try_from(METADATA_BYTES_V1).expect("metadata size fits u64"),
            ),
            (
                second_metadata_address,
                u64::try_from(METADATA_BYTES_V1).expect("metadata size fits u64"),
            ),
        ],
        8,
        &linked_bytes,
    );
    assert_linked_bytes(
        linked_payload_section,
        payload_address,
        inspected.payload(),
        &linked_bytes,
    );
    assert_linked_bytes(
        linked_payload_section,
        second_payload_address,
        second_inspected.payload(),
        &linked_bytes,
    );
    assert_linked_bytes(
        linked_metadata_section,
        metadata_address,
        inspected.metadata_bytes(),
        &linked_bytes,
    );
    assert_linked_bytes(
        linked_metadata_section,
        second_metadata_address,
        second_inspected.metadata_bytes(),
        &linked_bytes,
    );
    let execution = Command::new(&executable_path)
        .output()
        .expect("execute linked aggregate");
    assert!(
        execution.status.success(),
        "linked aggregate failed: status={:?} stderr={}",
        execution.status.code(),
        String::from_utf8_lossy(&execution.stderr)
    );

    let search_program =
        build_exact_literal::<Span>(b"needle", AnchorFlags::default(), ValidateLimits::default())
            .expect("search program");
    let search_image = emit_with_backend(
        &search_program,
        SearchBackendPolicy::AsimdV8,
        EmitLimits::default(),
    )
    .expect("Search V8 image");
    let search_object = emit_search_object(
        &search_image,
        BindingIdentity::new([0x3d; 32]).unwrap(),
        ObjectLimits::default(),
    )
    .expect("search object");
    let search_object_path = directory.path().join("search.o");
    let search_header_path = directory.path().join("fre_aot_search.h");
    let search_driver_path = directory.path().join("search_driver.c");
    let search_driver_object_path = directory.path().join("search_driver.o");
    let search_executable_path = directory.path().join("search_driver");
    let search_map_path = directory.path().join("search_driver.map");
    write_new(&search_object_path, search_object.as_bytes());
    write_new(
        &search_header_path,
        generated_header(&search_object).as_bytes(),
    );
    write_new(
        &search_driver_path,
        br#"#include "fre_aot_search.h"

int main(void) {
    static const uint8_t haystack[] = "xxneedleyy";
    static const uint8_t empty_anchor = 0;
    const size_t poison_start = (size_t)UINT64_C(0xa5a5a5a5a5a5a5a5);
    const size_t poison_end = (size_t)UINT64_C(0x5a5a5a5a5a5a5a5a);
    struct fre_aot_search_result_v1 result = {poison_start, poison_end};
    uint64_t no_match = FRE_AOT_SELECTED_ENTRY(
        haystack, sizeof(haystack) - 1u, 0u, 2u, &result);
    if (no_match != 0u ||
        result.start != poison_start || result.end != poison_end) {
        return 20;
    }
    result.start = poison_start;
    result.end = poison_end;
    uint64_t status = FRE_AOT_SELECTED_ENTRY(
        haystack, sizeof(haystack) - 1u, 0u, sizeof(haystack) - 1u, &result);
    if (status != 1u || result.start != 2u || result.end != 8u) {
        return 21;
    }
    if (FRE_AOT_SELECTED_METADATA.abi_kind != FRE_AOT_ABI_SEARCH_V1 ||
        FRE_AOT_SELECTED_METADATA.status_bits != 64u ||
        FRE_AOT_SELECTED_METADATA.entry_offset != 0u) {
        return 22;
    }
    struct fre_aot_search_result_v1 empty_result = {
        poison_start, poison_end
    };
    uint64_t empty_status = FRE_AOT_SELECTED_ENTRY(
        &empty_anchor, 0u, 0u, 0u, &empty_result);
    if (empty_status != 0u ||
        empty_result.start != poison_start || empty_result.end != poison_end) {
        return 23;
    }
    return 0;
}
"#,
    );
    let compile_search_driver = Command::new("/usr/bin/clang")
        .args(["-arch", "arm64", "-std=c11", "-Wall", "-Wextra", "-Werror"])
        .arg("-I")
        .arg(directory.path())
        .arg(&search_driver_path)
        .arg("-c")
        .arg("-o")
        .arg(&search_driver_object_path)
        .output()
        .expect("compile search driver");
    assert!(
        compile_search_driver.status.success(),
        "clang rejected search driver: {}",
        String::from_utf8_lossy(&compile_search_driver.stderr)
    );
    let search_link = Command::new("/usr/bin/clang")
        .args(["-arch", "arm64"])
        .arg(&search_driver_object_path)
        .arg(&search_object_path)
        .arg("-Wl,-fatal_warnings")
        .arg("-Wl,-segprot,__TEXT,rx,rx")
        .arg("-Wl,-segprot,__FRE_CONST,r,r")
        .arg(format!("-Wl,-map,{}", search_map_path.display()))
        .arg("-o")
        .arg(&search_executable_path)
        .output()
        .expect("link search driver");
    assert!(
        search_link.status.success(),
        "clang rejected search object: {}",
        String::from_utf8_lossy(&search_link.stderr)
    );
    let search_map = std::fs::read_to_string(&search_map_path).expect("retained search link map");
    let search_symbols = search_object.exported_symbols();
    assert_retained_provider(
        &search_map,
        &search_object_path,
        search_object.as_bytes(),
        &[
            search_symbols.entry().as_str(),
            search_symbols.payload().as_str(),
            search_symbols.metadata().as_str(),
        ],
    );
    let search_otool = Command::new("/usr/bin/otool")
        .arg("-l")
        .arg(&search_executable_path)
        .output()
        .expect("inspect linked search protections");
    assert!(search_otool.status.success());
    let search_otool_stdout = String::from_utf8_lossy(&search_otool.stdout);
    assert_eq!(
        search_otool_stdout.matches("sectname __fre_image").count(),
        1
    );
    assert_eq!(
        search_otool_stdout.matches("sectname __fre_meta").count(),
        1
    );
    assert_segment_protections(&search_otool_stdout, "__TEXT", &["0x00000005", "r-x"]);
    assert_segment_protections(&search_otool_stdout, "__FRE_CONST", &["0x00000001", "r--"]);
    let search_payload_section = linked_section(&search_otool_stdout, "__TEXT", "__fre_image");
    let search_metadata_section = linked_section(&search_otool_stdout, "__FRE_CONST", "__fre_meta");
    let search_nm = Command::new("/usr/bin/nm")
        .arg("-n")
        .arg(&search_executable_path)
        .output()
        .expect("inspect linked search symbols");
    assert!(search_nm.status.success());
    let search_nm_stdout = String::from_utf8_lossy(&search_nm.stdout);
    let search_payload_address =
        linked_symbol_address(&search_nm_stdout, search_symbols.payload().as_str());
    assert_eq!(
        linked_symbol_address(&search_nm_stdout, search_symbols.entry().as_str()),
        search_payload_address
    );
    let search_metadata_address =
        linked_symbol_address(&search_nm_stdout, search_symbols.metadata().as_str());
    let search_inspection = inspect_object(search_object.as_bytes(), ObjectLimits::default())
        .expect("inspect retained search object");
    let search_linked_bytes =
        std::fs::read(&search_executable_path).expect("read linked search image");
    assert_exact_section_layout(
        search_payload_section,
        &[(
            search_payload_address,
            u64::try_from(search_inspection.payload().len()).expect("search payload size fits u64"),
        )],
        16,
        &search_linked_bytes,
    );
    assert_exact_section_layout(
        search_metadata_section,
        &[(
            search_metadata_address,
            u64::try_from(METADATA_BYTES_V1).expect("metadata size fits u64"),
        )],
        8,
        &search_linked_bytes,
    );
    assert_linked_bytes(
        search_payload_section,
        search_payload_address,
        search_inspection.payload(),
        &search_linked_bytes,
    );
    assert_linked_bytes(
        search_metadata_section,
        search_metadata_address,
        search_inspection.metadata_bytes(),
        &search_linked_bytes,
    );
    let search_execution = Command::new(&search_executable_path)
        .output()
        .expect("execute linked search");
    assert!(
        search_execution.status.success(),
        "linked search failed: status={:?} stderr={}",
        search_execution.status.code(),
        String::from_utf8_lossy(&search_execution.stderr)
    );
}

#[test]
#[allow(
    clippy::too_many_lines,
    reason = "one native transaction proves the linked v2 provider, protection, bytes, and ABI contract"
)]
fn apple_tools_link_and_execute_count_v2_object() {
    let program = build_exact_aggregate::<Count>(b"abcdefghijklmnop", ValidateLimits::default())
        .expect("Count v2 program");
    let image =
        emit_count_v2(&program, CountEmitLimitsV2::default()).expect("audited Count v2 image");
    let binding = BindingIdentity::new([0x4e; 32]).unwrap();
    let object = emit_count_object_v2(&program, &image, binding, ObjectLimits::default())
        .expect("Count v2 Mach-O object");
    validate_count_object_v2(
        &program,
        &image,
        binding,
        object.as_bytes(),
        ObjectLimits::default(),
    )
    .expect("strict Count v2 object validation");

    let directory = PrivateDirectory::new();
    let object_path = directory.path().join("count_v2.o");
    let header_path = directory.path().join("fre_aot_count_v2.h");
    let driver_path = directory.path().join("count_v2_driver.c");
    let driver_object_path = directory.path().join("count_v2_driver.o");
    let executable_path = directory.path().join("count_v2_driver");
    let map_path = directory.path().join("count_v2_driver.map");
    write_new(&object_path, object.as_bytes());
    write_new(&header_path, generated_count_v2_header(&object).as_bytes());
    write_new(
        &driver_path,
        br#"#include "fre_aot_count_v2.h"

int main(void) {
    static const uint8_t haystack[] =
        "xxxxxxxxxxxxxxxabcdefghijklmnop--abcdefghijklmnop";
    static const uint8_t empty_anchor = 0;
    struct fre_aot_count_result_v2 result = {
        UINT64_C(0xa5a5a5a5a5a5a5a5)
    };
    uint64_t status = FRE_AOT_SELECTED_ENTRY(
        haystack, sizeof(haystack) - 1u, &result);
    if (status != 0u || result.value != 2u) {
        return 30;
    }
    struct fre_aot_count_result_v2 empty_result = {
        UINT64_C(0x5a5a5a5a5a5a5a5a)
    };
    uint64_t empty_status = FRE_AOT_SELECTED_ENTRY(
        &empty_anchor, 0u, &empty_result);
    if (empty_status != 0u || empty_result.value != 0u) {
        return 31;
    }
    if (FRE_AOT_SELECTED_METADATA.backend_version != UINT16_C(0xa002) ||
        FRE_AOT_SELECTED_METADATA.algorithm_version != UINT16_C(4) ||
        FRE_AOT_SELECTED_METADATA.abi_kind != FRE_AOT_ABI_COUNT_V2 ||
        FRE_AOT_SELECTED_METADATA.abi_schema != FRE_AOT_CALL_ABI_SCHEMA_V2 ||
        FRE_AOT_SELECTED_METADATA.literal_bytes != 16u ||
        FRE_AOT_SELECTED_METADATA.entry_offset != 0u) {
        return 32;
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
        .expect("compile Count v2 driver");
    assert!(
        compile.status.success(),
        "clang rejected Count v2 driver: {}",
        String::from_utf8_lossy(&compile.stderr)
    );
    let link = Command::new("/usr/bin/clang")
        .args(["-arch", "arm64"])
        .arg(&driver_object_path)
        .arg(&object_path)
        .arg("-Wl,-fatal_warnings")
        .arg("-Wl,-segprot,__TEXT,rx,rx")
        .arg("-Wl,-segprot,__FRE_CONST,r,r")
        .arg(format!("-Wl,-map,{}", map_path.display()))
        .arg("-o")
        .arg(&executable_path)
        .output()
        .expect("link Count v2 driver");
    assert!(
        link.status.success(),
        "clang rejected Count v2 object: {}",
        String::from_utf8_lossy(&link.stderr)
    );
    let symbols = object.exported_symbols();
    let link_map = std::fs::read_to_string(&map_path).expect("retained Count v2 link map");
    assert_retained_provider(
        &link_map,
        &object_path,
        object.as_bytes(),
        &[
            symbols.entry().as_str(),
            symbols.payload().as_str(),
            symbols.metadata().as_str(),
        ],
    );
    let linked_otool = Command::new("/usr/bin/otool")
        .arg("-l")
        .arg(&executable_path)
        .output()
        .expect("inspect linked Count v2 protections");
    assert!(linked_otool.status.success());
    let linked_otool_stdout = String::from_utf8_lossy(&linked_otool.stdout);
    assert_eq!(
        linked_otool_stdout.matches("sectname __fre_image").count(),
        1
    );
    assert_eq!(
        linked_otool_stdout.matches("sectname __fre_meta").count(),
        1
    );
    assert_segment_protections(&linked_otool_stdout, "__TEXT", &["0x00000005", "r-x"]);
    assert_segment_protections(&linked_otool_stdout, "__FRE_CONST", &["0x00000001", "r--"]);
    let payload_section = linked_section(&linked_otool_stdout, "__TEXT", "__fre_image");
    let metadata_section = linked_section(&linked_otool_stdout, "__FRE_CONST", "__fre_meta");
    let linked_nm = Command::new("/usr/bin/nm")
        .arg("-n")
        .arg(&executable_path)
        .output()
        .expect("inspect linked Count v2 symbols");
    assert!(linked_nm.status.success());
    let linked_nm_stdout = String::from_utf8_lossy(&linked_nm.stdout);
    let payload_address = linked_symbol_address(&linked_nm_stdout, symbols.payload().as_str());
    assert_eq!(
        linked_symbol_address(&linked_nm_stdout, symbols.entry().as_str()),
        payload_address
    );
    let metadata_address = linked_symbol_address(&linked_nm_stdout, symbols.metadata().as_str());
    let public_nm = Command::new("/usr/bin/nm")
        .arg("-gU")
        .arg(&executable_path)
        .output()
        .expect("inspect linked Count v2 public definitions");
    assert!(public_nm.status.success());
    let public_nm_stdout = String::from_utf8_lossy(&public_nm.stdout);
    for private_symbol in [
        symbols.entry().as_str(),
        symbols.payload().as_str(),
        symbols.metadata().as_str(),
    ] {
        assert!(
            !public_nm_stdout.contains(private_symbol),
            "private Count V2 implementation symbol remained externally visible: {private_symbol}"
        );
    }
    let inspection = inspect_count_object_v2(object.as_bytes(), ObjectLimits::default())
        .expect("inspect retained Count v2 object");
    let linked_bytes = std::fs::read(&executable_path).expect("read linked Count v2 image");
    assert_exact_section_layout(
        payload_section,
        &[(
            payload_address,
            u64::try_from(inspection.payload().len()).expect("payload size fits u64"),
        )],
        16,
        &linked_bytes,
    );
    assert_exact_section_layout(
        metadata_section,
        &[(
            metadata_address,
            u64::try_from(METADATA_BYTES_V2).expect("metadata size fits u64"),
        )],
        8,
        &linked_bytes,
    );
    assert_linked_bytes(
        payload_section,
        payload_address,
        inspection.payload(),
        &linked_bytes,
    );
    assert_linked_bytes(
        metadata_section,
        metadata_address,
        inspection.metadata_bytes(),
        &linked_bytes,
    );
    let execution = Command::new(&executable_path)
        .output()
        .expect("execute linked Count v2 object");
    assert!(
        execution.status.success(),
        "linked Count v2 failed: status={:?} stderr={}",
        execution.status.code(),
        String::from_utf8_lossy(&execution.stderr)
    );
}

fn c_array(bytes: &[u8]) -> String {
    if bytes.is_empty() {
        return "0".to_owned();
    }
    bytes
        .iter()
        .map(|byte| format!("0x{byte:02x}"))
        .collect::<Vec<_>>()
        .join(", ")
}

#[allow(
    clippy::arithmetic_side_effects,
    reason = "the reference loop is bounded by owned test slices and the admitted 0..=32-byte literal"
)]
fn successive_count(haystack: &[u8], literal: &[u8]) -> u64 {
    if literal.is_empty() {
        return u64::try_from(haystack.len()).unwrap() + 1;
    }
    let mut cursor = 0_usize;
    let mut count = 0_u64;
    while cursor + literal.len() <= haystack.len() {
        if haystack[cursor..cursor + literal.len()] == *literal {
            count += 1;
            cursor += literal.len();
        } else {
            cursor += 1;
        }
    }
    count
}

#[test]
#[allow(
    clippy::arithmetic_side_effects,
    clippy::too_many_lines,
    reason = "the exhaustive native matrix uses bounded fixture arithmetic and keeps all ABI cases in one transaction"
)]
fn apple_tools_execute_count_v2_every_width_alignment_tail_overlap_and_guard_boundary() {
    let directory = PrivateDirectory::new();
    let sentinel_path = directory.path().join("count_v2_abi_sentinel.s");
    let sentinel_object_path = directory.path().join("count_v2_abi_sentinel.o");
    // This wrapper preserves its caller's nonvolatile state, installs
    // independent x19-x22 and d8-d15 sentinels, invokes the generated entry,
    // and tags the returned status if the generated callee changed any of
    // them. The forced sparse fixture below reaches the localization block.
    write_new(
        &sentinel_path,
        br"
.text
.p2align 2
.globl _fre_aot_call_with_abi_sentinel
_fre_aot_call_with_abi_sentinel:
    sub sp, sp, #128
    stp x29, x30, [sp, #0]
    mov x29, sp
    stp x19, x20, [sp, #16]
    stp x21, x22, [sp, #32]
    stp d8, d9, [sp, #48]
    stp d10, d11, [sp, #64]
    stp d12, d13, [sp, #80]
    stp d14, d15, [sp, #96]

    mov x16, x0
    mov x0, x1
    mov x1, x2
    mov x2, x3

    mov x19, #0x119
    mov x20, #0x120
    mov x21, #0x121
    mov x22, #0x122
    mov x9, #0x808
    fmov d8, x9
    mov x9, #0x909
    fmov d9, x9
    mov x9, #0xa0a
    fmov d10, x9
    mov x9, #0xb0b
    fmov d11, x9
    mov x9, #0xc0c
    fmov d12, x9
    mov x9, #0xd0d
    fmov d13, x9
    mov x9, #0xe0e
    fmov d14, x9
    mov x9, #0xf0f
    fmov d15, x9

    blr x16
    str x0, [sp, #112]

    cmp x19, #0x119
    b.ne 1f
    cmp x20, #0x120
    b.ne 1f
    cmp x21, #0x121
    b.ne 1f
    cmp x22, #0x122
    b.ne 1f
    fmov x9, d8
    cmp x9, #0x808
    b.ne 1f
    fmov x9, d9
    cmp x9, #0x909
    b.ne 1f
    fmov x9, d10
    cmp x9, #0xa0a
    b.ne 1f
    fmov x9, d11
    cmp x9, #0xb0b
    b.ne 1f
    fmov x9, d12
    cmp x9, #0xc0c
    b.ne 1f
    fmov x9, d13
    cmp x9, #0xd0d
    b.ne 1f
    fmov x9, d14
    cmp x9, #0xe0e
    b.ne 1f
    fmov x9, d15
    cmp x9, #0xf0f
    b.ne 1f
    ldr x0, [sp, #112]
    b 2f

1:
    ldr x0, [sp, #112]
    mov x9, #1
    lsl x9, x9, #63
    orr x0, x0, x9

2:
    ldp d14, d15, [sp, #96]
    ldp d12, d13, [sp, #80]
    ldp d10, d11, [sp, #64]
    ldp d8, d9, [sp, #48]
    ldp x21, x22, [sp, #32]
    ldp x19, x20, [sp, #16]
    ldp x29, x30, [sp, #0]
    add sp, sp, #128
    ret
",
    );
    let compile_sentinel = Command::new("/usr/bin/clang")
        .args(["-arch", "arm64", "-c"])
        .arg(&sentinel_path)
        .arg("-o")
        .arg(&sentinel_object_path)
        .output()
        .expect("compile Count v2 ABI sentinel");
    assert!(
        compile_sentinel.status.success(),
        "clang rejected Count v2 ABI sentinel: {}",
        String::from_utf8_lossy(&compile_sentinel.stderr)
    );
    for width in 0_usize..=32 {
        let literal = if width != 0 && width.is_multiple_of(2) {
            vec![b'a'; width]
        } else {
            (0..width)
                .map(|index| b'A' + u8::try_from((index * 7) % 26).unwrap())
                .collect::<Vec<_>>()
        };
        let program = build_exact_aggregate::<Count>(&literal, ValidateLimits::default()).unwrap();
        let image = emit_count_v2(&program, CountEmitLimitsV2::default()).unwrap();
        let binding_byte = u8::try_from(width + 1).unwrap();
        let binding = BindingIdentity::new([binding_byte; 32]).unwrap();
        let object =
            emit_count_object_v2(&program, &image, binding, ObjectLimits::default()).unwrap();
        validate_count_object_v2(
            &program,
            &image,
            binding,
            object.as_bytes(),
            ObjectLimits::default(),
        )
        .unwrap();

        let mut fixture = vec![0xee; 3];
        fixture.extend_from_slice(&literal);
        fixture.push(0xef);
        fixture.extend_from_slice(&literal);
        fixture.extend_from_slice(&[0xed; 5]);
        let mut tail = vec![0xec; 7];
        tail.extend_from_slice(&literal);
        let overlap = if width == 0 {
            vec![0xeb; 19]
        } else if width.is_multiple_of(2) {
            vec![b'a'; width * 3 + (width / 2)]
        } else {
            let mut value = literal.clone();
            value.extend_from_slice(&literal);
            value.extend_from_slice(&literal);
            value
        };
        let fixture_expected = successive_count(&fixture, &literal);
        let tail_expected = successive_count(&tail, &literal);
        let overlap_expected = successive_count(&overlap, &literal);

        let suffix = format!("{width:02}");
        let object_path = directory.path().join(format!("count_v2_{suffix}.o"));
        let header_path = directory.path().join(format!("count_v2_{suffix}.h"));
        let driver_path = directory.path().join(format!("count_v2_{suffix}.c"));
        let driver_object_path = directory.path().join(format!("count_v2_driver_{suffix}.o"));
        let executable_path = directory.path().join(format!("count_v2_driver_{suffix}"));
        write_new(&object_path, object.as_bytes());
        let header = generated_count_v2_header(&object);
        write_new(&header_path, header.as_bytes());

        let mut driver = String::new();
        writeln!(&mut driver, "#include \"count_v2_{suffix}.h\"").unwrap();
        driver.push_str(
            "#include <stdint.h>\n#include <stddef.h>\n#include <string.h>\n\
             #include <sys/mman.h>\n#include <unistd.h>\n\n\
             typedef uint64_t (*fre_aot_count_entry_v2)(\n\
                 const uint8_t *, size_t, struct fre_aot_count_result_v2 *);\n\
             extern uint64_t fre_aot_call_with_abi_sentinel(\n\
                 fre_aot_count_entry_v2, const uint8_t *, size_t,\n\
                 struct fre_aot_count_result_v2 *);\n\n",
        );
        writeln!(
            &mut driver,
            "static const uint8_t fixture[] = {{{}}};",
            c_array(&fixture)
        )
        .unwrap();
        writeln!(
            &mut driver,
            "static const uint8_t tail_fixture[] = {{{}}};",
            c_array(&tail)
        )
        .unwrap();
        writeln!(
            &mut driver,
            "static const uint8_t overlap_fixture[] = {{{}}};",
            c_array(&overlap)
        )
        .unwrap();
        if width >= 2 {
            driver.push_str("static const uint8_t abi_sparse_fixture[256] = {0};\n");
        }
        driver.push_str(
            r"
struct guarded_result {
    uint64_t before;
    struct fre_aot_count_result_v2 result;
    uint64_t after;
};

static int run_case(
    const uint8_t *source,
    size_t len,
    uint64_t expected,
    size_t alignment,
    int boundary
) {
    long page_long = sysconf(_SC_PAGESIZE);
    if (page_long <= 0) {
        return 40;
    }
    size_t page = (size_t)page_long;
    uint8_t *mapping = mmap(
        NULL, page * 3u, PROT_NONE, MAP_PRIVATE | MAP_ANON, -1, 0);
    if (mapping == MAP_FAILED) {
        return 41;
    }
    uint8_t *middle = mapping + page;
    if (mprotect(middle, page, PROT_READ | PROT_WRITE) != 0) {
        (void)munmap(mapping, page * 3u);
        return 42;
    }
    uint8_t *haystack = boundary
        ? middle + page - (len == 0u ? 1u : len)
        : middle + 64u + alignment;
    if (len != 0u) {
        memcpy(haystack, source, len);
    }
    struct guarded_result guarded = {
        UINT64_C(0x1122334455667788),
        { UINT64_C(0xa5a5a5a5a5a5a5a5) },
        UINT64_C(0x8877665544332211)
    };
    uint64_t status = fre_aot_call_with_abi_sentinel(
        FRE_AOT_SELECTED_ENTRY, haystack, len, &guarded.result);
    int bad = status != 0u
        || guarded.result.value != expected
        || guarded.before != UINT64_C(0x1122334455667788)
        || guarded.after != UINT64_C(0x8877665544332211);
    (void)munmap(mapping, page * 3u);
    return bad ? 43 : 0;
}

int main(void) {
",
        );
        writeln!(
            &mut driver,
            "    for (size_t alignment = 0; alignment < 16u; ++alignment) {{\n\
             \tint result = run_case(fixture, {}u, UINT64_C({fixture_expected}), alignment, 0);\n\
             \tif (result != 0) return result;\n\
             }}",
            fixture.len()
        )
        .unwrap();
        writeln!(
            &mut driver,
            "    int tail_result = run_case(tail_fixture, {}u, UINT64_C({tail_expected}), 0u, 1);\n\
             \tif (tail_result != 0) return tail_result;",
            tail.len()
        )
        .unwrap();
        writeln!(
            &mut driver,
            "    int overlap_result = run_case(overlap_fixture, {}u, UINT64_C({overlap_expected}), 0u, 1);\n\
             \tif (overlap_result != 0) return overlap_result;",
            overlap.len()
        )
        .unwrap();
        if width >= 2 {
            driver.push_str(
                "    int abi_sparse_result = run_case(\n\
                 \t\tabi_sparse_fixture, sizeof(abi_sparse_fixture), UINT64_C(0), 3u, 0);\n\
                 \tif (abi_sparse_result != 0) return abi_sparse_result;\n",
            );
        }
        writeln!(
            &mut driver,
            "    if (FRE_AOT_SELECTED_METADATA.backend_version != UINT16_C(0xa002)\n\
             \t\t|| FRE_AOT_SELECTED_METADATA.algorithm_version != UINT16_C(4)\n\
             \t\t|| FRE_AOT_SELECTED_METADATA.abi_kind != FRE_AOT_ABI_COUNT_V2\n\
             \t\t|| FRE_AOT_SELECTED_METADATA.abi_schema != FRE_AOT_CALL_ABI_SCHEMA_V2\n\
             \t\t|| FRE_AOT_SELECTED_METADATA.output_kind != 1u\n\
             \t\t|| FRE_AOT_SELECTED_METADATA.literal_bytes != {width}u\n\
             \t\t|| FRE_AOT_SELECTED_METADATA.actual_features != UINT64_C({})\n\
             \t\t|| FRE_AOT_SELECTED_METADATA.allowed_features != UINT64_C(1)) return 44;\n\
             \treturn 0;\n}}",
            u8::from(width != 0)
        )
        .unwrap();
        write_new(&driver_path, driver.as_bytes());

        let compile = Command::new("/usr/bin/clang")
            .args(["-arch", "arm64", "-std=c11", "-Wall", "-Wextra", "-Werror"])
            .arg("-I")
            .arg(directory.path())
            .arg(&driver_path)
            .arg("-c")
            .arg("-o")
            .arg(&driver_object_path)
            .output()
            .expect("compile every-width Count v2 driver");
        assert!(
            compile.status.success(),
            "clang rejected width {width} Count v2 driver: {}",
            String::from_utf8_lossy(&compile.stderr)
        );
        let link = Command::new("/usr/bin/clang")
            .args(["-arch", "arm64"])
            .arg(&driver_object_path)
            .arg(&sentinel_object_path)
            .arg(&object_path)
            .arg("-Wl,-fatal_warnings")
            .arg("-Wl,-segprot,__TEXT,rx,rx")
            .arg("-Wl,-segprot,__FRE_CONST,r,r")
            .arg("-o")
            .arg(&executable_path)
            .output()
            .expect("link every-width Count v2 driver");
        assert!(
            link.status.success(),
            "clang rejected width {width} Count v2 object: {}",
            String::from_utf8_lossy(&link.stderr)
        );
        let execution = Command::new(&executable_path)
            .output()
            .expect("execute every-width linked Count v2 object");
        assert!(
            execution.status.success(),
            "linked Count v2 width {width} failed: status={:?} stderr={}",
            execution.status.code(),
            String::from_utf8_lossy(&execution.stderr)
        );
    }
}
