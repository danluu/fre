//! Opt-in, no-clock execution of the authenticated U1 Rebar payloads.

use std::env;
use std::fs;
use std::os::unix::fs::MetadataExt;
use std::path::Path;
use std::process::Command;

use rebar_compare::current_fre_rebar_aggregate_operation_lifecycle;
use serde_json::Value;
use sha2::{Digest, Sha256};

const CASES_SHA256: &str = "02a8df2e25d3c2ccad44b8dc9cc9d0a76e80dcc37f38d14938c4e562f701ae45";
const TARGETS: [&str; 13] = [
    "imported/rsc/medium-1mb@rust/regex::steady-public-operation",
    "imported/rsc/medium-1mb@rust/regex::first-public-operation",
    "imported/rsc/easy1-1mb@rust/regex::steady-public-operation",
    "imported/rsc/easy1-1mb@rust/regex::first-public-operation",
    "opt/reverse-anchored/word-end@rust/regex::steady-public-operation",
    "imported/rsc/medium-32k@rust/regex::steady-public-operation",
    "imported/rsc/easy1-32k@rust/regex::steady-public-operation",
    "opt/fixed-length/go33484-1@rust/regex::steady-public-operation",
    "opt/fixed-length/go33484-2@rust/regex::steady-public-operation",
    "opt/fixed-length/go33484-3@rust/regex::steady-public-operation",
    "imported/rsc/medium-1k@rust/regex::steady-public-operation",
    "imported/rsc/easy1-1k@rust/regex::steady-public-operation",
    "imported/rsc/anchored-literal-long-non-match@rust/regex::steady-public-operation",
];

#[derive(Debug)]
struct Klv {
    name: String,
    model: String,
    case_insensitive: bool,
    unicode: bool,
    patterns: Vec<String>,
    haystack: Vec<u8>,
}

fn sha256(bytes: &[u8]) -> String {
    let mut digest = Sha256::new();
    digest.update(bytes);
    format!("{:x}", digest.finalize())
}

fn scalar_utf8(key: &str, value: &[u8]) -> String {
    String::from_utf8(value.to_vec()).unwrap_or_else(|error| panic!("{key} is not UTF-8: {error}"))
}

fn scalar_bool(key: &str, value: &[u8]) -> bool {
    match value {
        b"true" => true,
        b"false" => false,
        _ => panic!("{key} is not a canonical boolean"),
    }
}

fn parse_klv(bytes: &[u8]) -> Klv {
    let mut name = None;
    let mut model = None;
    let mut case_insensitive = None;
    let mut unicode = None;
    let mut patterns = Vec::new();
    let mut haystack = None;
    let mut cursor = 0_usize;
    while cursor < bytes.len() {
        let key_end = bytes[cursor..]
            .iter()
            .position(|&byte| byte == b':')
            .map(|offset| cursor.checked_add(offset).expect("KLV key offset overflow"))
            .expect("KLV key delimiter");
        let length_start = key_end.checked_add(1).expect("KLV key end overflow");
        let length_end = bytes[length_start..]
            .iter()
            .position(|&byte| byte == b':')
            .map(|offset| {
                length_start
                    .checked_add(offset)
                    .expect("KLV length offset overflow")
            })
            .expect("KLV length delimiter");
        let key = std::str::from_utf8(&bytes[cursor..key_end]).expect("KLV key UTF-8");
        let length = std::str::from_utf8(&bytes[length_start..length_end])
            .expect("KLV length UTF-8")
            .parse::<usize>()
            .expect("KLV canonical length");
        let value_start = length_end.checked_add(1).expect("KLV length end overflow");
        let value_end = value_start
            .checked_add(length)
            .expect("KLV length overflow");
        assert_eq!(bytes.get(value_end), Some(&b'\n'), "{key} terminator");
        let value = &bytes[value_start..value_end];
        match key {
            "name" => assert!(name.replace(scalar_utf8(key, value)).is_none()),
            "model" => assert!(model.replace(scalar_utf8(key, value)).is_none()),
            "case-insensitive" => {
                assert!(case_insensitive.replace(scalar_bool(key, value)).is_none());
            }
            "unicode" => assert!(unicode.replace(scalar_bool(key, value)).is_none()),
            "max-iters" => assert_eq!(value, b"1"),
            "max-warmup-iters" | "max-time" | "max-warmup-time" => {
                assert_eq!(value, b"0");
            }
            "pattern" => patterns.push(scalar_utf8(key, value)),
            "haystack" => assert!(haystack.replace(value.to_vec()).is_none()),
            _ => panic!("unexpected KLV key {key:?}"),
        }
        cursor = value_end.checked_add(1).expect("KLV record end overflow");
    }
    Klv {
        name: name.expect("KLV name"),
        model: model.expect("KLV model"),
        case_insensitive: case_insensitive.expect("KLV case-insensitive"),
        unicode: unicode.expect("KLV unicode"),
        patterns,
        haystack: haystack.expect("KLV haystack"),
    }
}

fn required_string<'a>(row: &'a Value, key: &str) -> &'a str {
    row.get(key)
        .and_then(Value::as_str)
        .unwrap_or_else(|| panic!("row lacks string {key}"))
}

fn current_euid() -> u32 {
    let output = Command::new("/usr/bin/id")
        .arg("-u")
        .output()
        .expect("run /usr/bin/id -u");
    assert!(output.status.success());
    std::str::from_utf8(&output.stdout)
        .expect("id output UTF-8")
        .trim()
        .parse::<u32>()
        .expect("numeric effective uid")
}

#[test]
#[ignore = "requires the authenticated U1 case catalog and KLV CAS"]
#[allow(
    clippy::too_many_lines,
    reason = "one no-clock gate authenticates and executes the exact thirteen imported KLV payloads"
)]
fn authenticated_u1_exact_thirteen_klv_execute_without_clock() {
    let cases_path = env::var_os("FRE_U1_CASES_JSON").expect("FRE_U1_CASES_JSON");
    let cas_root = env::var_os("FRE_U1_KLV_CAS_ROOT").expect("FRE_U1_KLV_CAS_ROOT");
    let cases_bytes = fs::read(&cases_path).expect("read authenticated U1 cases");
    assert_eq!(sha256(&cases_bytes), CASES_SHA256);
    let catalog: Value = serde_json::from_slice(&cases_bytes).expect("parse U1 cases");
    let rows = catalog
        .get("cases")
        .and_then(Value::as_array)
        .expect("U1 cases array");
    let euid = current_euid();

    for target in TARGETS {
        let row = rows
            .iter()
            .find(|row| row.get("case_id").and_then(Value::as_str) == Some(target))
            .unwrap_or_else(|| panic!("missing target {target}"));
        let klv_digest = required_string(row, "klv_sha256");
        assert_eq!(klv_digest.len(), 64);
        let klv_path = Path::new(&cas_root)
            .join(&klv_digest[..2])
            .join(format!("{klv_digest}.klv"));
        let metadata = fs::symlink_metadata(&klv_path).expect("KLV metadata");
        assert!(metadata.file_type().is_file());
        assert!(!metadata.file_type().is_symlink());
        assert_eq!(metadata.mode() & 0o777, 0o444);
        assert_eq!(metadata.nlink(), 1);
        assert_eq!(metadata.uid(), euid);
        let klv_bytes = fs::read(&klv_path).expect("read KLV");
        assert_eq!(sha256(&klv_bytes), klv_digest);
        let klv = parse_klv(&klv_bytes);
        assert_eq!(klv.name, required_string(row, "benchmark"), "{target}");
        assert_eq!(klv.model, required_string(row, "model"), "{target}");
        assert_eq!(
            klv.case_insensitive,
            row.get("case_insensitive")
                .and_then(Value::as_bool)
                .expect("case_insensitive"),
            "{target}"
        );
        assert_eq!(
            klv.unicode,
            row.get("unicode")
                .and_then(Value::as_bool)
                .expect("unicode"),
            "{target}"
        );
        assert_eq!(
            u64::try_from(klv.haystack.len()).expect("haystack length fits u64"),
            row.get("haystack_bytes")
                .and_then(Value::as_u64)
                .expect("haystack_bytes"),
            "{target}"
        );
        assert_eq!(
            sha256(&klv.haystack),
            required_string(row, "haystack_sha256"),
            "{target}"
        );
        let expected_patterns: Vec<&str> = row
            .get("patterns")
            .and_then(Value::as_array)
            .expect("patterns")
            .iter()
            .map(|pattern| required_string(pattern, "value"))
            .collect();
        assert_eq!(
            klv.patterns.iter().map(String::as_str).collect::<Vec<_>>(),
            expected_patterns,
            "{target}"
        );
        let expected = row
            .get("expected")
            .and_then(Value::as_u64)
            .expect("expected");
        let lifecycle = current_fre_rebar_aggregate_operation_lifecycle(
            &klv.model,
            &klv.patterns,
            klv.unicode,
            klv.case_insensitive,
            klv.haystack.len(),
        )
        .unwrap_or_else(|error| panic!("{target} build: {error}"));
        assert_eq!(
            lifecycle.plan(),
            "aggregate-continuation-program",
            "{target}"
        );
        assert_eq!(
            lifecycle
                .execute(&klv.haystack)
                .unwrap_or_else(|error| panic!("{target} first: {error}")),
            expected,
            "{target}"
        );
        assert_eq!(
            lifecycle
                .execute(&klv.haystack)
                .unwrap_or_else(|error| panic!("{target} steady: {error}")),
            expected,
            "{target}"
        );
    }
}
