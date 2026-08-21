//! Public regressions for the four old dd6 aggregate status-3 exclusions.

use std::{
    collections::BTreeSet,
    env,
    error::Error,
    fmt::Write as _,
    fs,
    path::{Path, PathBuf},
    process::{Command, Stdio},
    time::SystemTime,
};

use bstr::ByteSlice;
use fre_aot_rebar_runner::shared::{self, Benchmark, Model};
use fre_aot_regex::{CompiledRegex, CpuFeature, FeatureSet, Target};
use regex_automata::meta::Regex;

type DynError = Box<dyn Error + Send + Sync + 'static>;

#[derive(Clone, Copy, Debug)]
struct Regression {
    benchmark: &'static str,
    model: Model,
}

#[derive(Clone, Copy, Debug)]
struct TargetCase {
    label: &'static str,
    target: Target,
}

const REGRESSIONS: &[Regression] = &[
    Regression {
        benchmark: "curated/03-date/unicode",
        model: Model::SpanSum,
    },
    Regression {
        benchmark: "hyperscan/fixed-length-words-unicode-nosom",
        model: Model::Count,
    },
    Regression {
        benchmark: "unicode/codepoints/letters-lower-or-upper",
        model: Model::Count,
    },
    Regression {
        benchmark: "wild/url/search",
        model: Model::SpanSum,
    },
];

#[test]
fn mandatory_matrix_retains_all_four_public_dd6_status3_rows() {
    let actual = REGRESSIONS
        .iter()
        .map(|regression| (regression.benchmark, regression.model))
        .collect::<Vec<_>>();
    assert_eq!(
        actual,
        [
            ("curated/03-date/unicode", Model::SpanSum),
            ("hyperscan/fixed-length-words-unicode-nosom", Model::Count),
            ("unicode/codepoints/letters-lower-or-upper", Model::Count),
            ("wild/url/search", Model::SpanSum),
        ]
    );
}

#[test]
fn mandatory_c_harness_keeps_handles_opaque_and_routes_isolated() {
    let source = c_source(
        "linked_program",
        123,
        "linked_reducer",
        "public_helper",
        "private_helper",
        &[0; 32],
        Model::Count.prepare_operation_flags(),
        0,
        17,
    );
    assert!(!source.contains("((const unsigned char*)"));
    assert!(!source.contains("search_exclusive"));
    assert!(!source.contains("fill_spans_exclusive"));
    assert!(source.contains("linked_reducer(aggregate_handle"));
    assert!(source.contains("linked_reducer(legacy_handle"));
    assert!(source.contains("private_helper(private_handle"));
    assert!(source.contains("public_helper(public_handle"));
    assert!(source.contains("fre_aot_regex_runtime_prepare_exclusive_v2"));
    assert!(source.contains("fre_aot_regex_runtime_prepare_exclusive_v3"));
    assert!(source.contains("first_status!=0U||first!=UINT64_C(17)"));
    assert!(source.contains("steady_status!=0U||steady!=UINT64_C(17)"));
}

#[test]
#[ignore = "recursive Cargo smoke for the configured build-script and linked-runner path"]
fn configured_build_script_and_runner_execute_end_to_end() -> Result<(), DynError> {
    let nonce = SystemTime::now()
        .duration_since(SystemTime::UNIX_EPOCH)?
        .as_nanos();
    let root = env::temp_dir().join(format!(
        "fre-aot-rebar-configured-smoke-{}-{nonce}",
        std::process::id()
    ));
    fs::create_dir(&root)?;

    let result = (|| {
        let klv_bytes = configured_smoke_klv();
        let benchmark = Benchmark::parse(&klv_bytes)?;
        let expected = oracle(&benchmark)?;
        let klv = root.join("configured-smoke.klv");
        let target = root.join("target");
        fs::write(&klv, &klv_bytes)?;

        let cargo = env::var_os("CARGO").unwrap_or_else(|| "cargo".into());
        let built = Command::new(cargo)
            .current_dir(workspace_root())
            .args([
                "build",
                "--offline",
                "--jobs=2",
                "-p",
                "fre-aot-rebar-runner",
                "--bin",
                "fre-aot-rebar-runner",
            ])
            .env("CARGO_TARGET_DIR", &target)
            .env("FRE_AOT_REBAR_KLV", &klv)
            .env("FRE_AOT_REBAR_FEATURES", "none")
            .env("FRE_AOT_REBAR_SOURCE_COMMIT", "configured-smoke")
            .env("FRE_AOT_REBAR_SOURCE_TREE", "configured-smoke")
            .output()?;
        if !built.status.success() {
            return Err(format!(
                "configured runner build failed: stdout={} stderr={}",
                String::from_utf8_lossy(&built.stdout),
                String::from_utf8_lossy(&built.stderr),
            )
            .into());
        }

        let runner = target.join("debug").join(format!(
            "fre-aot-rebar-runner{}",
            std::env::consts::EXE_SUFFIX
        ));
        let executed = Command::new(&runner)
            .stdin(Stdio::from(fs::File::open(&klv)?))
            .output()?;
        if !executed.status.success() {
            return Err(format!(
                "configured runner failed: status={:?} stdout={} stderr={}",
                executed.status.code(),
                String::from_utf8_lossy(&executed.stdout),
                String::from_utf8_lossy(&executed.stderr),
            )
            .into());
        }
        let stdout = std::str::from_utf8(&executed.stdout)?;
        let lines = stdout.lines().collect::<Vec<_>>();
        if lines.len() != 1 {
            return Err(format!(
                "configured runner emitted {} samples instead of one: {stdout:?}",
                lines.len()
            )
            .into());
        }
        let (duration, actual) = lines[0]
            .split_once(',')
            .ok_or("configured runner sample is not nanoseconds,value")?;
        duration
            .parse::<u128>()
            .map_err(|error| format!("configured runner duration is invalid: {error}"))?;
        let actual = actual
            .parse::<u64>()
            .map_err(|error| format!("configured runner value is invalid: {error}"))?;
        if actual != expected {
            return Err(format!(
                "configured runner returned {actual}, independent oracle returned {expected}"
            )
            .into());
        }

        let provenance = Command::new(&runner).arg("--provenance").output()?;
        if !provenance.status.success() {
            return Err(format!(
                "configured runner provenance failed: {}",
                String::from_utf8_lossy(&provenance.stderr)
            )
            .into());
        }
        let provenance = std::str::from_utf8(&provenance.stdout)?;
        for expected_field in [
            "schema=fre.aot.rebar-runner.v2",
            "configured=true",
            "model=count",
            "benchmark=\"synthetic/aot-runner/configured-smoke\"",
            "source_commit=configured-smoke",
            "source_tree=configured-smoke",
            "prepare_config_version=2",
            "required_prepare_capabilities=0000000000000000",
            "max_handle_bytes=0",
            "max_ordered_nfa_scratch_bytes=0",
            "max_ordered_nfa_setup_work=0",
        ] {
            if !provenance.contains(expected_field) {
                return Err(format!(
                    "configured runner provenance omitted {expected_field:?}: {provenance}"
                )
                .into());
            }
        }
        Ok(())
    })();
    match result {
        Ok(()) => {
            fs::remove_dir_all(&root)?;
            Ok(())
        }
        Err(error) => {
            eprintln!(
                "preserving failed configured-runner smoke at {}",
                root.display()
            );
            Err(error)
        }
    }
}

fn configured_smoke_klv() -> Vec<u8> {
    let mut output = Vec::new();
    for (key, value) in [
        ("name", b"synthetic/aot-runner/configured-smoke".as_slice()),
        ("model", b"count".as_slice()),
        ("case-insensitive", b"false".as_slice()),
        ("unicode", b"false".as_slice()),
        ("max-iters", b"1".as_slice()),
        ("max-warmup-iters", b"0".as_slice()),
        ("max-time", b"1000000000".as_slice()),
        ("max-warmup-time", b"0".as_slice()),
        ("pattern", b"a+".as_slice()),
        ("haystack", b"baa x aaa".as_slice()),
    ] {
        output.extend_from_slice(format!("{key}:{}:", value.len()).as_bytes());
        output.extend_from_slice(value);
        output.push(b'\n');
    }
    output
}

#[test]
#[ignore = "recursive Cargo smoke for the helper-free linked native-row bridge"]
fn configured_native_row_bridge_activates_later_entries_and_matches_build_many()
-> Result<(), DynError> {
    let nonce = SystemTime::now()
        .duration_since(SystemTime::UNIX_EPOCH)?
        .as_nanos();
    let root = env::temp_dir().join(format!(
        "fre-aot-rebar-native-rows-{}-{nonce}",
        std::process::id()
    ));
    fs::create_dir(&root)?;

    let result = (|| {
        let cargo = env::var_os("CARGO").unwrap_or_else(|| "cargo".into());
        for (index, model) in [Model::Count, Model::SpanSum].into_iter().enumerate() {
            let klv_bytes = configured_native_rows_klv(model);
            let benchmark = Benchmark::parse(&klv_bytes)?;
            let expected = oracle(&benchmark)?;
            let klv = root.join(format!("native-rows-{index}.klv"));
            let target = root.join(format!("target-{index}"));
            fs::write(&klv, &klv_bytes)?;

            let built = Command::new(&cargo)
                .current_dir(workspace_root())
                .args([
                    "build",
                    "--offline",
                    "--jobs=2",
                    "-p",
                    "fre-aot-rebar-runner",
                    "--bin",
                    "fre-aot-rebar-runner",
                ])
                .env("CARGO_TARGET_DIR", &target)
                .env("FRE_AOT_REBAR_KLV", &klv)
                .env("FRE_AOT_REBAR_FEATURES", "none")
                .env("FRE_AOT_REBAR_SOURCE_COMMIT", "native-row-smoke")
                .env("FRE_AOT_REBAR_SOURCE_TREE", "native-row-smoke")
                .output()?;
            if !built.status.success() {
                return Err(format!(
                    "configured native-row build failed for {model:?}: stdout={} stderr={}",
                    String::from_utf8_lossy(&built.stdout),
                    String::from_utf8_lossy(&built.stderr),
                )
                .into());
            }

            let runner = target.join("debug").join(format!(
                "fre-aot-rebar-runner{}",
                std::env::consts::EXE_SUFFIX
            ));
            let executed = Command::new(&runner)
                .stdin(Stdio::from(fs::File::open(&klv)?))
                .output()?;
            if !executed.status.success() {
                return Err(format!(
                    "configured native-row runner failed for {model:?}: stdout={} stderr={}",
                    String::from_utf8_lossy(&executed.stdout),
                    String::from_utf8_lossy(&executed.stderr),
                )
                .into());
            }
            let stdout = std::str::from_utf8(&executed.stdout)?;
            let (_, actual) = stdout
                .trim()
                .split_once(',')
                .ok_or("native-row output is not nanoseconds,value")?;
            let actual = actual.parse::<u64>()?;
            if actual != expected {
                return Err(format!(
                    "native-row {model:?} returned {actual}, build-many oracle returned {expected}"
                )
                .into());
            }

            let provenance = Command::new(&runner).arg("--provenance").output()?;
            if !provenance.status.success() {
                return Err(format!(
                    "native-row provenance failed for {model:?}: {}",
                    String::from_utf8_lossy(&provenance.stderr)
                )
                .into());
            }
            let provenance = std::str::from_utf8(&provenance.stdout)?;
            for expected_field in [
                "schema=fre.aot.rebar-runner.v3",
                "native_row_bridge=true",
                "source_pattern_count=5",
                "source_to_artifact=0,1,2,1,3",
                "component_count=4",
                "aggregate_strategy=native-independent-span-row-selector-v1",
                "boundary=complete-native-row-bridge",
            ] {
                if !provenance.contains(expected_field) {
                    return Err(format!(
                        "native-row provenance omitted {expected_field:?}: {provenance}"
                    )
                    .into());
                }
            }
            for component in 0..4 {
                for expected_field in [
                    format!("component_{component}_native=true"),
                    format!("component_{component}_source_ordinal="),
                    format!("component_{component}_entry_symbol="),
                    format!("component_{component}_runtime_symbols="),
                    format!("component_{component}_program_sha256="),
                    format!("component_{component}_object_sha256="),
                ] {
                    if !provenance.contains(&expected_field) {
                        return Err(format!(
                            "native-row provenance omitted {expected_field:?}: {provenance}"
                        )
                        .into());
                    }
                }
            }
        }
        Ok(())
    })();
    match result {
        Ok(()) => {
            fs::remove_dir_all(&root)?;
            Ok(())
        }
        Err(error) => {
            eprintln!("preserving failed native-row smoke at {}", root.display());
            Err(error)
        }
    }
}

fn configured_native_rows_klv(model: Model) -> Vec<u8> {
    let mut output = Vec::new();
    let model = model.name().as_bytes();
    for (key, value) in [
        ("name", b"synthetic/aot-runner/native-row-bridge".as_slice()),
        ("model", model),
        ("case-insensitive", b"false".as_slice()),
        ("unicode", b"false".as_slice()),
        ("max-iters", b"1".as_slice()),
        ("max-warmup-iters", b"0".as_slice()),
        ("max-time", b"1000000000".as_slice()),
        ("max-warmup-time", b"0".as_slice()),
        ("pattern", b"z+".as_slice()),
        ("pattern", b"ab".as_slice()),
        ("pattern", b"a".as_slice()),
        ("pattern", b"ab".as_slice()),
        ("pattern", b"".as_slice()),
        ("haystack", b"abx".as_slice()),
    ] {
        output.extend_from_slice(format!("{key}:{}:", value.len()).as_bytes());
        output.extend_from_slice(value);
        output.push(b'\n');
    }
    output
}

#[test]
#[ignore = "recursive Cargo smoke for all fixed regex-redux AOT objects and entries"]
fn configured_regex_redux_links_and_executes_all_native_components() -> Result<(), DynError> {
    let nonce = SystemTime::now()
        .duration_since(SystemTime::UNIX_EPOCH)?
        .as_nanos();
    let root = env::temp_dir().join(format!(
        "fre-aot-rebar-regex-redux-smoke-{}-{nonce}",
        std::process::id()
    ));
    fs::create_dir(&root)?;
    let result = (|| {
        let klv_bytes = regex_redux_smoke_klv();
        let benchmark = Benchmark::parse(&klv_bytes)?;
        if benchmark.model != Model::RegexRedux || !benchmark.patterns.is_empty() {
            return Err("regex-redux smoke did not retain its typed zero-pattern shape".into());
        }
        let klv = root.join("regex-redux-smoke.klv");
        let target = root.join("target");
        fs::write(&klv, &klv_bytes)?;

        let cargo = env::var_os("CARGO").unwrap_or_else(|| "cargo".into());
        let built = Command::new(cargo)
            .current_dir(workspace_root())
            .args([
                "build",
                "--offline",
                "--jobs=2",
                "-p",
                "fre-aot-rebar-runner",
                "--bin",
                "fre-aot-rebar-runner",
            ])
            .env("CARGO_TARGET_DIR", &target)
            .env("FRE_AOT_REBAR_KLV", &klv)
            .env("FRE_AOT_REBAR_FEATURES", "none")
            .env("FRE_AOT_REBAR_SOURCE_COMMIT", "regex-redux-smoke")
            .env("FRE_AOT_REBAR_SOURCE_TREE", "regex-redux-smoke")
            .output()?;
        if !built.status.success() {
            return Err(format!(
                "regex-redux runner build/link failed: stdout={} stderr={}",
                String::from_utf8_lossy(&built.stdout),
                String::from_utf8_lossy(&built.stderr),
            )
            .into());
        }

        let runner = target.join("debug").join(format!(
            "fre-aot-rebar-runner{}",
            std::env::consts::EXE_SUFFIX
        ));
        let executed = Command::new(&runner)
            .stdin(Stdio::from(fs::File::open(&klv)?))
            .output()?;
        if !executed.status.success()
            || executed.stdout.lines().count() != 1
            || !executed.stdout.ends_with(b",8\n")
        {
            return Err(format!(
                "regex-redux runner failed or returned the wrong final length: status={:?} stdout={} stderr={}",
                executed.status.code(),
                String::from_utf8_lossy(&executed.stdout),
                String::from_utf8_lossy(&executed.stderr),
            )
            .into());
        }
        let provenance = Command::new(&runner).arg("--provenance").output()?;
        if !provenance.status.success() {
            return Err(format!(
                "regex-redux provenance failed: {}",
                String::from_utf8_lossy(&provenance.stderr)
            )
            .into());
        }
        let provenance = std::str::from_utf8(&provenance.stdout)?;
        for expected_field in [
            "schema=fre.aot.rebar-runner.v3",
            "model=regex-redux",
            "benchmark=\"synthetic/aot-runner/regex-redux-smoke\"",
            "component_count=15",
            "boundary=complete-regex-redux-aot-precompiled",
        ] {
            if !provenance.contains(expected_field) {
                return Err(format!(
                    "regex-redux provenance omitted {expected_field:?}: {provenance}"
                )
                .into());
            }
        }
        for component in 0..15 {
            for expected_field in [
                format!("component_{component}_native=true"),
                format!("component_{component}_entry_symbol="),
                format!("component_{component}_runtime_symbols="),
                format!("component_{component}_program_sha256="),
                format!("component_{component}_object_sha256="),
            ] {
                if !provenance.contains(&expected_field) {
                    return Err(format!(
                        "regex-redux provenance omitted {expected_field:?}: {provenance}"
                    )
                    .into());
                }
            }
        }
        Ok(())
    })();
    match result {
        Ok(()) => {
            fs::remove_dir_all(&root)?;
            Ok(())
        }
        Err(error) => {
            eprintln!("preserving failed regex-redux smoke at {}", root.display());
            Err(error)
        }
    }
}

fn regex_redux_smoke_klv() -> Vec<u8> {
    let mut output = Vec::new();
    for (key, value) in [
        ("name", b"synthetic/aot-runner/regex-redux-smoke".as_slice()),
        ("model", b"regex-redux".as_slice()),
        ("case-insensitive", b"false".as_slice()),
        ("unicode", b"false".as_slice()),
        ("max-iters", b"1".as_slice()),
        ("max-warmup-iters", b"0".as_slice()),
        ("max-time", b"1000000000".as_slice()),
        ("max-warmup-time", b"0".as_slice()),
        ("haystack", b">test\nagggtaaa\n".as_slice()),
    ] {
        output.extend_from_slice(format!("{key}:{}:", value.len()).as_bytes());
        output.extend_from_slice(value);
        output.push(b'\n');
    }
    output
}

#[test]
#[ignore = "recursive Cargo smoke for linked prepared Span-fill refills and nullable progress"]
fn configured_count_spans_uses_linked_span_fill_across_refills() -> Result<(), DynError> {
    const KEYWORD_PATTERN: &str = r"\b(Self|a(?:bstract|s)|b(?:ecome|o(?:ol|x)|reak)|c(?:har|on(?:st|tinue)|rate)|do|e(?:lse|num|xtern)|f(?:32|64|alse|inal|n|or)|i(?:1(?:28|6)|32|64|mpl|size|[8fn])|l(?:et|oop)|m(?:a(?:cro|tch)|o(?:d|ve)|ut)|override|p(?:riv|ub)|re(?:f|turn)|s(?:elf|t(?:atic|r(?:(?:uct)?))|uper)|t(?:r(?:ait|ue|y)|ype(?:(?:of)?))|u(?:1(?:28|6)|32|64|8|ns(?:afe|ized)|s(?:(?:(?:iz)?)e))|virtual|wh(?:(?:er|il)e)|yield)\b";

    let keyword_haystack = "self ".repeat(130).into_bytes();
    let nullable_pattern = format!("(?:{KEYWORD_PATTERN}|)");
    let nullable_haystack = vec![b'!'; 130];
    let cases = [
        (
            "synthetic/aot-runner/span-fill-refill",
            KEYWORD_PATTERN,
            keyword_haystack.as_slice(),
            false,
        ),
        (
            "synthetic/aot-runner/span-fill-nullable",
            nullable_pattern.as_str(),
            nullable_haystack.as_slice(),
            true,
        ),
    ];

    let nonce = SystemTime::now()
        .duration_since(SystemTime::UNIX_EPOCH)?
        .as_nanos();
    let root = env::temp_dir().join(format!(
        "fre-aot-rebar-span-fill-smoke-{}-{nonce}",
        std::process::id()
    ));
    fs::create_dir(&root)?;
    let result = (|| {
        let target = root.join("target");
        let cargo = env::var_os("CARGO").unwrap_or_else(|| "cargo".into());
        for (index, (name, pattern, haystack, must_be_nullable)) in cases.into_iter().enumerate() {
            let klv_bytes = configured_count_spans_klv(name, pattern, haystack);
            let benchmark = Benchmark::parse(&klv_bytes)?;
            let regex = oracle_regex(&benchmark)?;
            let match_count = regex.find_iter(&benchmark.haystack).count();
            if match_count <= 64 {
                return Err(format!(
                    "configured Span-fill smoke {name} has only {match_count} matches"
                )
                .into());
            }
            let is_nullable = regex
                .find(b"")
                .is_some_and(|matched| matched.start() == matched.end());
            if is_nullable != must_be_nullable {
                return Err(format!(
                    "configured Span-fill smoke {name} nullable={is_nullable}, expected {must_be_nullable}"
                )
                .into());
            }
            let expected = oracle(&benchmark)?;
            let klv = root.join(format!("span-fill-{index}.klv"));
            fs::write(&klv, &klv_bytes)?;

            let built = Command::new(&cargo)
                .current_dir(workspace_root())
                .args([
                    "build",
                    "--offline",
                    "--jobs=2",
                    "-p",
                    "fre-aot-rebar-runner",
                    "--bin",
                    "fre-aot-rebar-runner",
                ])
                .env("CARGO_TARGET_DIR", &target)
                .env("FRE_AOT_REBAR_KLV", &klv)
                .env("FRE_AOT_REBAR_FEATURES", "none")
                .env("FRE_AOT_REBAR_SOURCE_COMMIT", "span-fill-smoke")
                .env("FRE_AOT_REBAR_SOURCE_TREE", "span-fill-smoke")
                .output()?;
            if !built.status.success() {
                return Err(format!(
                    "configured Span-fill build failed for {name}: stdout={} stderr={}",
                    String::from_utf8_lossy(&built.stdout),
                    String::from_utf8_lossy(&built.stderr),
                )
                .into());
            }

            let runner = target.join("debug").join(format!(
                "fre-aot-rebar-runner{}",
                std::env::consts::EXE_SUFFIX
            ));
            let provenance = Command::new(&runner).arg("--provenance").output()?;
            if !provenance.status.success() {
                return Err(format!(
                    "configured Span-fill provenance failed for {name}: {}",
                    String::from_utf8_lossy(&provenance.stderr)
                )
                .into());
            }
            let provenance = std::str::from_utf8(&provenance.stdout)?;
            for required in [
                "schema=fre.aot.rebar-runner.v2",
                "adapter=general-aot-linked-complete-spans-prepared-v3-required-ordered-nfa-v15",
                "aggregate_strategy=Some(NativeOrderedNfaFused)",
                "prepared_bulk_strategy=Some(NativeOrderedNfaLoop)",
                "span_iteration_strategy=linked-prepared-span-fill-64::Some(NativeOrderedNfaLoop)",
                "prepare_config_version=3",
                "required_prepare_capabilities=0000000000000001",
                "max_handle_bytes=8388608",
                "max_ordered_nfa_scratch_bytes=8388608",
                "max_ordered_nfa_setup_work=2000000",
                "span_fill_symbol=fre_aot_regex_fill_spans_exclusive_v1_",
                "required_comparators=rust-regex-1.12.4,fre-current-runtime",
            ] {
                if !provenance.contains(required) {
                    return Err(format!(
                        "configured Span-fill provenance for {name} omitted {required:?}: {provenance}"
                    )
                    .into());
                }
            }

            let executed = Command::new(&runner)
                .stdin(Stdio::from(fs::File::open(&klv)?))
                .output()?;
            if !executed.status.success() {
                return Err(format!(
                    "configured Span-fill runner failed for {name}: status={:?} stdout={} stderr={}",
                    executed.status.code(),
                    String::from_utf8_lossy(&executed.stdout),
                    String::from_utf8_lossy(&executed.stderr),
                )
                .into());
            }
            let stdout = std::str::from_utf8(&executed.stdout)?;
            let (_, actual) = stdout
                .trim()
                .split_once(',')
                .ok_or("configured Span-fill sample is not nanoseconds,value")?;
            let actual = actual.parse::<u64>()?;
            if actual != expected {
                return Err(format!(
                    "configured Span-fill returned {actual} for {name}, oracle returned {expected}"
                )
                .into());
            }
        }
        Ok(())
    })();
    match result {
        Ok(()) => {
            fs::remove_dir_all(&root)?;
            Ok(())
        }
        Err(error) => {
            eprintln!(
                "preserving failed configured Span-fill smoke at {}",
                root.display()
            );
            Err(error)
        }
    }
}

fn configured_count_spans_klv(name: &str, pattern: &str, haystack: &[u8]) -> Vec<u8> {
    let mut output = Vec::new();
    for (key, value) in [
        ("name", name.as_bytes()),
        ("model", b"count-spans".as_slice()),
        ("case-insensitive", b"false".as_slice()),
        ("unicode", b"true".as_slice()),
        ("max-iters", b"1".as_slice()),
        ("max-warmup-iters", b"0".as_slice()),
        ("max-time", b"1000000000".as_slice()),
        ("max-warmup-time", b"0".as_slice()),
        ("pattern", pattern.as_bytes()),
        ("haystack", haystack),
    ] {
        output.extend_from_slice(format!("{key}:{}:", value.len()).as_bytes());
        output.extend_from_slice(value);
        output.push(b'\n');
    }
    output
}

#[test]
#[ignore = "requires public Rebar checkout paths and a prebuilt fre-aot-regex-runtime static library"]
fn public_dd6_status3_exclusions_pass_first_and_steady_on_current_main() -> Result<(), DynError> {
    let rebar = required_path("FRE_REBAR_BIN")?;
    let benchmark_dir = rebar_benchmark_dir(required_path("FRE_REBAR_BENCH_DIR")?)?;
    let runtime = static_runtime()?;
    let target_filter = env::var("FRE_AOT_REBAR_TARGET_FILTER").ok();
    let benchmark_filter = env::var("FRE_AOT_REBAR_BENCHMARK_FILTER").ok();
    if let Some(benchmark) = benchmark_filter.as_deref()
        && !REGRESSIONS
            .iter()
            .any(|regression| regression.benchmark == benchmark)
    {
        return Err(format!("unknown mandatory benchmark filter {benchmark:?}").into());
    }
    let targets = executable_target_matrix()?
        .into_iter()
        .filter(|target| {
            target_filter
                .as_deref()
                .is_none_or(|filter| filter == target.label)
        })
        .collect::<Vec<_>>();
    if targets.is_empty() {
        return Err(
            format!("mandatory target filter {target_filter:?} selected no host tier").into(),
        );
    }
    let selected_rows_per_target = if benchmark_filter.is_some() {
        1
    } else {
        REGRESSIONS.len()
    };
    let expected_rows = targets
        .len()
        .checked_mul(selected_rows_per_target)
        .ok_or("mandatory diagnostic row count overflow")?;
    let nonce = SystemTime::now()
        .duration_since(SystemTime::UNIX_EPOCH)?
        .as_nanos();
    let root = env::temp_dir().join(format!(
        "fre-aot-rebar-dd6-status3-{}-{nonce}",
        std::process::id()
    ));
    fs::create_dir(&root)?;

    let result = (|| {
        let mut executed_rows = 0_usize;
        for target in targets {
            executed_rows = executed_rows
                .checked_add(run_regressions(
                    &root,
                    &rebar,
                    &benchmark_dir,
                    &runtime,
                    target,
                    benchmark_filter.as_deref(),
                )?)
                .ok_or("mandatory diagnostic row count overflow")?;
        }
        if executed_rows != expected_rows {
            return Err(format!(
                "mandatory base/SIMD matrix executed {executed_rows} rows instead of {expected_rows}"
            )
            .into());
        }
        Ok(())
    })();
    match result {
        Ok(()) => {
            fs::remove_dir_all(&root)?;
            Ok(())
        }
        Err(error) => {
            eprintln!(
                "preserving failed mandatory status-3 diagnostic at {}",
                root.display()
            );
            Err(error)
        }
    }
}

fn executable_target_matrix() -> Result<Vec<TargetCase>, String> {
    let base = shared::target_from_parts(
        std::env::consts::ARCH,
        std::env::consts::OS,
        FeatureSet::EMPTY.bits(),
    )?;
    let mut targets = vec![TargetCase {
        label: "base",
        target: base,
    }];

    #[cfg(target_arch = "aarch64")]
    {
        if !std::arch::is_aarch64_feature_detected!("neon") {
            return Err("host AArch64 does not report the mandatory ASIMD/NEON tier".to_owned());
        }
        targets.push(TargetCase {
            label: "asimd",
            target: shared::target_from_parts(
                std::env::consts::ARCH,
                std::env::consts::OS,
                FeatureSet::of(CpuFeature::Aarch64Asimd).bits(),
            )?,
        });
    }

    #[cfg(target_arch = "x86_64")]
    if std::arch::is_x86_feature_detected!("avx2") {
        targets.push(TargetCase {
            label: "avx2",
            target: shared::target_from_parts(
                std::env::consts::ARCH,
                std::env::consts::OS,
                FeatureSet::of(CpuFeature::X86Avx2).bits(),
            )?,
        });
    }

    Ok(targets)
}

fn run_regressions(
    root: &Path,
    rebar: &Path,
    definitions: &Path,
    runtime: &Path,
    target_case: TargetCase,
    benchmark_filter: Option<&str>,
) -> Result<usize, DynError> {
    let mut names = BTreeSet::new();
    for (index, regression) in REGRESSIONS.iter().enumerate() {
        if benchmark_filter.is_some_and(|filter| filter != regression.benchmark) {
            continue;
        }
        if !names.insert(regression.benchmark) {
            return Err(format!("duplicate mandatory regression {}", regression.benchmark).into());
        }
        let benchmark = public_klv(rebar, definitions, regression.benchmark)?;
        if benchmark.name != regression.benchmark || benchmark.model != regression.model {
            return Err(format!(
                "mandatory regression identity changed: expected {} {:?}, got {} {:?}",
                regression.benchmark, regression.model, benchmark.name, benchmark.model
            )
            .into());
        }
        let expected = oracle(&benchmark)?;
        let compiled = shared::compile_benchmark(&benchmark, target_case.target)?;
        let strategy = compiled
            .receipt()
            .prepared_aggregate_strategy
            .ok_or("mandatory regression omitted aggregate strategy")?;
        eprintln!(
            "mandatory-status3 target={} features={:#018x} benchmark={} model={} strategy={strategy:?}",
            target_case.label,
            target_case.target.features.bits(),
            regression.benchmark,
            regression.model.name(),
        );
        let (program_symbol, program_len) = compiled
            .module()
            .required_runtime_program()
            .ok_or("mandatory regression omitted runtime program")?;
        let reducer_symbol = match regression.model {
            Model::Count => compiled
                .module()
                .prepared_count_symbol()
                .ok_or("mandatory Count symbol absent")?,
            Model::SpanSum => compiled
                .module()
                .prepared_span_sum_symbol()
                .ok_or("mandatory SpanSum symbol absent")?,
            Model::Compile | Model::GrepCount => {
                return Err("mandatory dd6 matrix contains an unexpected model".into());
            }
        };
        let case_dir = root.join(format!("{}-case-{index}", target_case.label));
        fs::create_dir(&case_dir)?;
        let object = case_dir.join("artifact.o");
        let program = case_dir.join("program.bin");
        let aggregate_identity = case_dir.join("aggregate-identity.bin");
        let haystack = case_dir.join("haystack.bin");
        let source = case_dir.join("runner.c");
        let executable = case_dir.join("runner");
        let program_bytes = symbol_bytes(&compiled, program_symbol)?;
        if program_bytes.len() != program_len {
            return Err(format!(
                "required runtime program extent mismatch: symbol={} bytes={} required={program_len}",
                program_symbol,
                program_bytes.len()
            )
            .into());
        }
        let identity_bytes =
            symbol_bytes(&compiled, ".Lfre_aot_regex_prepared_aggregate_identity")?;
        let serialized_program = compiled.program().serialize()?;
        if program_bytes != serialized_program {
            return Err(
                "required runtime program differs from CompiledProgram serialization".into(),
            );
        }
        if compiled.program().serialized_sha256()? != compiled.receipt().program_sha256 {
            return Err("receipt program SHA differs from exact serialized program".into());
        }
        if identity_bytes != compiled.receipt().program_sha256 {
            return Err("aggregate-local identity disagrees with semantic artifact".into());
        }
        eprintln!(
            "mandatory-status3-detail target={} engine={:?} start={:?} bulk={:?} prepared_entry={:?} span_fill={:?} program_symbol={} reducer_symbol={} program_sha256={} artifact_identity={} aggregate_identity={}",
            target_case.label,
            compiled.receipt().engine,
            compiled.receipt().start_accelerator,
            compiled.module().prepared_bulk_strategy(),
            compiled.module().prepared_entry_symbol(),
            compiled.module().prepared_span_fill_symbol(),
            program_symbol,
            reducer_symbol,
            hex(&compiled.receipt().program_sha256),
            hex(&compiled.receipt().program_sha256),
            hex(identity_bytes),
        );
        fs::write(&object, compiled.object())?;
        fs::write(&program, program_bytes)?;
        fs::write(&aggregate_identity, identity_bytes)?;
        fs::write(&haystack, &benchmark.haystack)?;
        fs::write(
            &source,
            c_source(
                program_symbol,
                program_len,
                reducer_symbol,
                runtime_reducer_symbol(regression.model)?,
                runtime_private_reducer_symbol(regression.model)?,
                &compiled.receipt().program_sha256,
                regression.model.prepare_operation_flags(),
                compiled.receipt().required_prepare_capabilities,
                expected,
            ),
        )?;
        let compiler = if cfg!(target_os = "macos") {
            "clang"
        } else {
            "cc"
        };
        let linked = Command::new(compiler)
            .args(["-O2", "-std=c11"])
            .arg(&source)
            .arg(&object)
            .arg(runtime)
            .arg("-o")
            .arg(&executable)
            .output()?;
        if !linked.status.success() {
            return Err(format!(
                "link mandatory regression {} target={} ({strategy:?}): {}",
                regression.benchmark,
                target_case.label,
                String::from_utf8_lossy(&linked.stderr)
            )
            .into());
        }
        let executed = Command::new(&executable).arg(&haystack).output()?;
        if !executed.status.success() {
            return Err(format!(
                "mandatory regression {} target={} ({strategy:?}) failed first/steady: status={:?}, stdout={}, stderr={}",
                regression.benchmark,
                target_case.label,
                executed.status.code(),
                String::from_utf8_lossy(&executed.stdout),
                String::from_utf8_lossy(&executed.stderr)
            )
            .into());
        }
    }
    let expected_rows = if benchmark_filter.is_some() {
        1
    } else {
        REGRESSIONS.len()
    };
    if names.len() != expected_rows {
        return Err(format!(
            "mandatory dd6 status-3 matrix selected {} jobs instead of {expected_rows}",
            names.len()
        )
        .into());
    }
    Ok(names.len())
}

fn public_klv(rebar: &Path, definitions: &Path, benchmark: &str) -> Result<Benchmark, DynError> {
    let output = Command::new(rebar)
        .args(["klv", "--max-iters", "1", "--max-warmup-iters", "0"])
        .args(["--max-time", "1ns", "--max-warmup-time", "0ns"])
        .arg("--dir")
        .arg(definitions)
        .arg(benchmark)
        .output()?;
    if !output.status.success() {
        return Err(format!(
            "public Rebar KLV generation failed for {benchmark}: {}",
            String::from_utf8_lossy(&output.stderr)
        )
        .into());
    }
    Benchmark::parse(&output.stdout).map_err(Into::into)
}

fn oracle(benchmark: &Benchmark) -> Result<u64, String> {
    let regex = oracle_regex(benchmark)?;
    match benchmark.model {
        Model::Count => u64::try_from(regex.find_iter(&benchmark.haystack).count())
            .map_err(|_| "Count oracle overflow".to_owned()),
        Model::SpanSum => regex
            .find_iter(&benchmark.haystack)
            .try_fold(0_u64, |sum, matched| {
                let width = u64::try_from(matched.end().saturating_sub(matched.start()))
                    .map_err(|_| "span width overflow".to_owned())?;
                sum.checked_add(width)
                    .ok_or_else(|| "SpanSum oracle overflow".to_owned())
            }),
        Model::GrepCount => benchmark.haystack.lines().try_fold(0_u64, |count, line| {
            if regex.is_match(line) {
                count
                    .checked_add(1)
                    .ok_or_else(|| "grep oracle overflow".to_owned())
            } else {
                Ok(count)
            }
        }),
        Model::Compile => Err("mandatory dd6 matrix contains no compile model".to_owned()),
    }
}

fn oracle_regex(benchmark: &Benchmark) -> Result<Regex, String> {
    let config = Regex::config()
        .utf8_empty(false)
        .nfa_size_limit(Some(104_857_600));
    let syntax = regex_automata::util::syntax::Config::new()
        .utf8(false)
        .unicode(benchmark.unicode)
        .case_insensitive(benchmark.case_insensitive);
    Regex::builder()
        .configure(config)
        .syntax(syntax)
        .build_many(&benchmark.patterns)
        .map_err(|error| format!("Rust Rebar oracle compilation failed: {error}"))
}

fn c_source(
    program_symbol: &str,
    program_len: usize,
    reducer_symbol: &str,
    runtime_reducer_symbol: &str,
    runtime_private_reducer_symbol: &str,
    artifact_identity: &[u8; 32],
    operation_flags: u64,
    required_prepare_capabilities: u64,
    expected: u64,
) -> String {
    let identity_initializer =
        artifact_identity
            .iter()
            .fold(String::with_capacity(32 * 6), |mut output, byte| {
                if !output.is_empty() {
                    output.push(',');
                }
                write!(output, "0x{byte:02x}").expect("format identity byte into String");
                output
            });
    let mut source = String::new();
    writeln!(
        source,
        r#"#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
typedef void *handle_t;
typedef struct {{uint32_t struct_size;uint32_t config_version;uint64_t operation_flags;uint64_t max_start_filter_setup_work;uint64_t max_grep_count_workspace_bytes;uint64_t reserved[4];}} prepare_v2_t;
typedef struct {{uint32_t struct_size;uint32_t config_version;uint64_t operation_flags;uint64_t max_start_filter_setup_work;uint64_t max_grep_count_workspace_bytes;uint64_t v2_reserved[4];uint64_t max_handle_bytes;uint64_t max_ordered_nfa_scratch_bytes;uint64_t max_ordered_nfa_setup_work;uint64_t required_capabilities;uint64_t reserved[2];}} prepare_v3_t;
static const unsigned char expected_identity[32]={{{identity_initializer}}};
extern const unsigned char {program_symbol}[];
extern uint32_t {reducer_symbol}(handle_t,const unsigned char*,size_t,uint64_t*);
extern uint32_t {runtime_reducer_symbol}(handle_t,const unsigned char*,size_t,uint64_t*);
extern uint32_t {runtime_private_reducer_symbol}(handle_t,const unsigned char*,size_t,uint64_t*,const unsigned char*);
extern uint32_t fre_aot_regex_runtime_prepare_exclusive_v1(const unsigned char*,size_t,handle_t*);
extern uint32_t fre_aot_regex_runtime_prepare_exclusive_v2(const unsigned char*,size_t,const prepare_v2_t*,handle_t*);
extern uint32_t fre_aot_regex_runtime_prepare_exclusive_v3(const unsigned char*,size_t,const prepare_v3_t*,handle_t*);
extern uint32_t fre_aot_regex_runtime_destroy_exclusive_v1(handle_t);
int main(int argc,char **argv){{
  if(argc!=2)return 1;
  FILE *file=fopen(argv[1],"rb");if(!file)return 2;
  if(fseek(file,0,SEEK_END)!=0)return 3;
  long raw=ftell(file);if(raw<0)return 4;
  if(fseek(file,0,SEEK_SET)!=0)return 5;
  size_t len=(size_t)raw;
  unsigned char *bytes=(unsigned char*)malloc(len?len:1U);if(!bytes)return 6;
  if(len&&fread(bytes,1,len,file)!=len)return 7;
  if(fclose(file)!=0)return 8;
  handle_t aggregate_handle=0;
  uint32_t prepare_status;
  if(UINT64_C({required_prepare_capabilities})==0){{
    const prepare_v2_t config={{64U,2U,UINT64_C({operation_flags}),UINT64_C(100000000),UINT64_C(67108864),{{0,0,0,0}}}};
    prepare_status=fre_aot_regex_runtime_prepare_exclusive_v2({program_symbol},{program_len}U,&config,&aggregate_handle);
  }}else{{
    const prepare_v3_t config={{112U,3U,UINT64_C({operation_flags}),UINT64_C(100000000),UINT64_C(67108864),{{0,0,0,0}},UINT64_C(8388608),UINT64_C(8388608),UINT64_C(2000000),UINT64_C({required_prepare_capabilities}),{{0,0}}}};
    prepare_status=fre_aot_regex_runtime_prepare_exclusive_v3({program_symbol},{program_len}U,&config,&aggregate_handle);
  }}
  if(prepare_status!=0U)return 9;
  uint64_t first=UINT64_C(0xaaaaaaaaaaaaaaaa),steady=UINT64_C(0xbbbbbbbbbbbbbbbb);
  uint32_t first_status={reducer_symbol}(aggregate_handle,bytes,len,&first);
  uint32_t steady_status={reducer_symbol}(aggregate_handle,bytes,len,&steady);
  if(fre_aot_regex_runtime_destroy_exclusive_v1(aggregate_handle)!=0U)return 10;
  printf("aggregate-first=%u,%llu aggregate-steady=%u,%llu\n",first_status,(unsigned long long)first,steady_status,(unsigned long long)steady);
  fflush(stdout);
  if(first_status!=0U||first!=UINT64_C({expected}))return 11;
  if(steady_status!=0U||steady!=UINT64_C({expected}))return 12;
  handle_t legacy_handle=0;
  if(fre_aot_regex_runtime_prepare_exclusive_v1({program_symbol},{program_len}U,&legacy_handle)!=0U)return 13;
  uint64_t legacy=UINT64_C(0xeeeeeeeeeeeeeeee);
  uint32_t legacy_status={reducer_symbol}(legacy_handle,bytes,len,&legacy);
  if(fre_aot_regex_runtime_destroy_exclusive_v1(legacy_handle)!=0U)return 14;
  if(legacy_status!=0U||legacy!=UINT64_C({expected}))return 15;
  handle_t private_handle=0;
  if(fre_aot_regex_runtime_prepare_exclusive_v1({program_symbol},{program_len}U,&private_handle)!=0U)return 16;
  uint64_t private_helper=UINT64_C(0xdddddddddddddddd);
  uint32_t private_helper_status={runtime_private_reducer_symbol}(private_handle,bytes,len,&private_helper,expected_identity);
  if(fre_aot_regex_runtime_destroy_exclusive_v1(private_handle)!=0U)return 17;
  if(private_helper_status!=0U||private_helper!=UINT64_C({expected}))return 18;
  handle_t public_handle=0;
  if(fre_aot_regex_runtime_prepare_exclusive_v1({program_symbol},{program_len}U,&public_handle)!=0U)return 19;
  uint64_t helper=UINT64_C(0xcccccccccccccccc);
  uint32_t helper_status={runtime_reducer_symbol}(public_handle,bytes,len,&helper);
  if(fre_aot_regex_runtime_destroy_exclusive_v1(public_handle)!=0U)return 20;
  free(bytes);
  printf("legacy-wrapper=%u,%llu private-helper=%u,%llu public-helper=%u,%llu\n",legacy_status,(unsigned long long)legacy,private_helper_status,(unsigned long long)private_helper,helper_status,(unsigned long long)helper);
  if(helper_status!=0U||helper!=UINT64_C({expected}))return 21;
  return 0;
}}"#
    )
    .expect("format mandatory C harness");
    source
}

fn runtime_private_reducer_symbol(model: Model) -> Result<&'static str, DynError> {
    match model {
        Model::Count => Ok("fre_aot_regex_runtime_compiler_private_count_exclusive_v1"),
        Model::SpanSum => Ok("fre_aot_regex_runtime_compiler_private_span_sum_exclusive_v1"),
        Model::Compile | Model::GrepCount => {
            Err("mandatory dd6 matrix contains an unexpected private reducer".into())
        }
    }
}

fn runtime_reducer_symbol(model: Model) -> Result<&'static str, DynError> {
    match model {
        Model::Count => Ok("fre_aot_regex_runtime_count_exclusive_v1"),
        Model::SpanSum => Ok("fre_aot_regex_runtime_span_sum_exclusive_v1"),
        Model::Compile | Model::GrepCount => {
            Err("mandatory dd6 matrix contains an unexpected reducer".into())
        }
    }
}

fn symbol_bytes<'a>(compiled: &'a CompiledRegex, name: &str) -> Result<&'a [u8], DynError> {
    let symbol = compiled
        .module()
        .symbols()
        .iter()
        .find(|symbol| symbol.name == name)
        .ok_or_else(|| format!("compiled module omitted symbol {name}"))?;
    let section = symbol
        .section
        .ok_or_else(|| format!("compiled symbol {name} is undefined"))?;
    let start = usize::try_from(symbol.offset)?;
    let size = usize::try_from(symbol.size)?;
    let end = start
        .checked_add(size)
        .ok_or_else(|| format!("compiled symbol {name} extent overflow"))?;
    compiled
        .module()
        .sections()
        .get(section)
        .and_then(|section| section.bytes().get(start..end))
        .ok_or_else(|| format!("compiled symbol {name} extent is outside its section").into())
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().fold(
        String::with_capacity(bytes.len().saturating_mul(2)),
        |mut output, byte| {
            write!(output, "{byte:02x}").expect("format byte into String");
            output
        },
    )
}

fn required_path(name: &str) -> Result<PathBuf, DynError> {
    env::var_os(name)
        .map(PathBuf::from)
        .ok_or_else(|| format!("{name} is required").into())
}

fn rebar_benchmark_dir(path: PathBuf) -> Result<PathBuf, DynError> {
    if path.join("definitions").is_dir() && path.join("haystacks").is_dir() {
        return Ok(path);
    }
    if path.file_name().is_some_and(|name| name == "definitions") {
        if let Some(parent) = path.parent() {
            if parent.join("definitions").is_dir() && parent.join("haystacks").is_dir() {
                return Ok(parent.to_owned());
            }
        }
    }
    Err(format!(
        "FRE_REBAR_BENCH_DIR must contain definitions/ and haystacks/ (or name its definitions/ child): {}",
        path.display()
    )
    .into())
}

fn static_runtime() -> Result<PathBuf, DynError> {
    let executable = env::current_exe()?;
    let profile = executable
        .parent()
        .and_then(Path::parent)
        .ok_or("test executable has no Cargo profile directory")?;
    let runtime = profile.join("libfre_aot_regex_runtime.a");
    if !runtime.is_file() {
        return Err(format!(
            "build the runtime first: cargo build -p fre-aot-regex-runtime --lib ({})",
            runtime.display()
        )
        .into());
    }
    require_fresh_static_runtime(&runtime)?;
    Ok(runtime)
}

fn require_fresh_static_runtime(runtime: &Path) -> Result<(), DynError> {
    let runtime_metadata = fs::metadata(runtime)?;
    if runtime_metadata.len() == 0 {
        return Err(format!("static runtime archive is empty: {}", runtime.display()).into());
    }
    let runtime_modified = runtime_metadata.modified()?;
    let workspace = workspace_root();
    let mut newest = None;
    for relative in ["Cargo.toml", "Cargo.lock"] {
        record_newest_source(&workspace.join(relative), &mut newest)?;
    }
    for package in [
        "fre-aot-regex-runtime",
        "fre-aot-regex",
        "fre-automata",
        "fre-capture-lab",
        "fre-exact-alloc",
        "fre-lower",
        "fre-re2-syntax",
        "fre-simd-kernels",
        "fre-syntax",
        "fre-target-features",
    ] {
        record_newest_source(&workspace.join("crates").join(package), &mut newest)?;
    }
    if let Some((modified, source)) = newest {
        if modified > runtime_modified {
            return Err(format!(
                "static runtime {} is older than {}; rebuild fre-aot-regex-runtime with the current sources before running this diagnostic",
                runtime.display(),
                source.display(),
            )
            .into());
        }
    }
    Ok(())
}

fn record_newest_source(
    path: &Path,
    newest: &mut Option<(SystemTime, PathBuf)>,
) -> Result<(), DynError> {
    if path.is_dir() {
        for entry in fs::read_dir(path)? {
            let entry = entry?;
            let file_type = entry.file_type()?;
            if file_type.is_dir() {
                record_newest_source(&entry.path(), newest)?;
            } else if file_type.is_file() && is_runtime_source(&entry.path()) {
                record_newest_source(&entry.path(), newest)?;
            }
        }
        return Ok(());
    }
    if !path.is_file() {
        return Err(format!("runtime freshness input is absent: {}", path.display()).into());
    }
    let modified = fs::metadata(path)?.modified()?;
    if newest
        .as_ref()
        .is_none_or(|(current, _)| modified > *current)
    {
        *newest = Some((modified, path.to_owned()));
    }
    Ok(())
}

fn is_runtime_source(path: &Path) -> bool {
    path.file_name().is_some_and(|name| name == "Cargo.toml")
        || path.extension().is_some_and(|extension| {
            extension == "rs" || extension == "c" || extension == "h" || extension == "S"
        })
}

fn workspace_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../..")
}
