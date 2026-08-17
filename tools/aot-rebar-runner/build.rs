#[allow(
    dead_code,
    unreachable_pub,
    reason = "the build script shares the runtime KLV/compiler types but consumes only build identity fields"
)]
#[path = "src/shared.rs"]
mod shared;

use std::{env, fmt::Write as _, fs, path::PathBuf};

use fre_aot_regex::{CpuFeature, FeatureSet};

const KLV_ENV: &str = "FRE_AOT_REBAR_KLV";
const FEATURES_ENV: &str = "FRE_AOT_REBAR_FEATURES";
const SOURCE_COMMIT_ENV: &str = "FRE_AOT_REBAR_SOURCE_COMMIT";
const SOURCE_TREE_ENV: &str = "FRE_AOT_REBAR_SOURCE_TREE";
const GENERATED_FILE: &str = "linked_artifact.rs";
const OBJECT_FILE: &str = "aot-rebar-artifact.o";

fn main() {
    println!("cargo:rerun-if-env-changed={KLV_ENV}");
    println!("cargo:rerun-if-env-changed={FEATURES_ENV}");
    println!("cargo:rerun-if-env-changed={SOURCE_COMMIT_ENV}");
    println!("cargo:rerun-if-env-changed={SOURCE_TREE_ENV}");
    let output = PathBuf::from(env::var_os("OUT_DIR").expect("Cargo sets OUT_DIR"));
    let object_path = output.join(OBJECT_FILE);
    let generated_path = output.join(GENERATED_FILE);
    let Some(klv_path) = env::var_os(KLV_ENV).map(PathBuf::from) else {
        fs::write(&object_path, []).expect("write unconfigured object sentinel");
        fs::write(&generated_path, stub_source()).expect("write unconfigured bindings");
        println!(
            "cargo:warning=fre-aot-rebar-runner is unconfigured; set {KLV_ENV} to an absolute public Rebar KLV path"
        );
        return;
    };
    assert!(klv_path.is_absolute(), "{KLV_ENV} must be an absolute path");
    println!("cargo:rerun-if-changed={}", klv_path.display());

    let bytes = fs::read(&klv_path)
        .unwrap_or_else(|error| panic!("read {} named by {KLV_ENV}: {error}", klv_path.display()));
    assert!(
        u64::try_from(bytes.len()).is_ok_and(|length| length <= shared::MAX_KLV_BYTES),
        "build KLV exceeds {} bytes",
        shared::MAX_KLV_BYTES
    );
    let benchmark = shared::Benchmark::parse(&bytes).expect("parse public Rebar build KLV");
    let feature_bits = parse_features(
        env::var(FEATURES_ENV)
            .unwrap_or_else(|_| "none".to_owned())
            .as_str(),
    );
    let architecture = env::var("CARGO_CFG_TARGET_ARCH").expect("Cargo target architecture");
    let operating_system = env::var("CARGO_CFG_TARGET_OS").expect("Cargo target operating system");
    let target = shared::target_from_parts(&architecture, &operating_system, feature_bits)
        .expect("supported general AOT build target");
    let source_commit =
        env::var(SOURCE_COMMIT_ENV).unwrap_or_else(|_| "unbound-development".to_owned());
    let source_tree =
        env::var(SOURCE_TREE_ENV).unwrap_or_else(|_| "unbound-development".to_owned());
    let compiled =
        shared::compile_benchmark(&benchmark, target).expect("compile public Rebar build artifact");
    let (program_symbol, program_len) = compiled
        .module()
        .required_runtime_program()
        .expect("prepared reducer publishes its exact runtime program");
    let reducer_symbol = match benchmark.model {
        shared::Model::Compile | shared::Model::Count => compiled
            .module()
            .prepared_count_symbol()
            .expect("Count export"),
        shared::Model::SpanSum => compiled
            .module()
            .prepared_span_sum_symbol()
            .expect("SpanSum export"),
        shared::Model::GrepCount => compiled
            .module()
            .prepared_grep_count_symbol()
            .expect("GrepCount export"),
    };
    fs::write(&object_path, compiled.object()).expect("write linked general AOT object");
    fs::write(
        &generated_path,
        configured_source(
            &benchmark,
            &compiled,
            &object_path,
            program_symbol,
            program_len,
            reducer_symbol,
            &architecture,
            &operating_system,
            feature_bits,
            &source_commit,
            &source_tree,
        ),
    )
    .expect("write linked general AOT bindings");
    println!(
        "cargo:rustc-link-arg-bin=fre-aot-rebar-runner={}",
        object_path.display()
    );
}

fn parse_features(value: &str) -> u64 {
    if value.is_empty() || value == "none" {
        return FeatureSet::EMPTY.bits();
    }
    let mut features = FeatureSet::EMPTY;
    for name in value.split(',') {
        let feature = match name {
            "sse2" => CpuFeature::X86Sse2,
            "avx2" => CpuFeature::X86Avx2,
            "avx512f" => CpuFeature::X86Avx512F,
            "avx512bw" => CpuFeature::X86Avx512Bw,
            "avx512vl" => CpuFeature::X86Avx512Vl,
            "asimd" => CpuFeature::Aarch64Asimd,
            "sve" => CpuFeature::Aarch64Sve,
            "sve2" => CpuFeature::Aarch64Sve2,
            other => panic!("unknown {FEATURES_ENV} feature {other:?}"),
        };
        features = features.with(feature);
    }
    features.bits()
}

#[allow(
    clippy::too_many_arguments,
    reason = "the generated binding binds every audited artifact identity component explicitly"
)]
fn configured_source(
    benchmark: &shared::Benchmark,
    compiled: &fre_aot_regex::CompiledRegex,
    object_path: &std::path::Path,
    program_symbol: &str,
    program_len: usize,
    reducer_symbol: &str,
    architecture: &str,
    operating_system: &str,
    feature_bits: u64,
    source_commit: &str,
    source_tree: &str,
) -> String {
    let receipt = compiled.receipt();
    let runtime_symbols = compiled
        .module()
        .required_runtime_symbols()
        .collect::<Vec<_>>()
        .join(",");
    let mut source = String::new();
    writeln!(source, "pub const CONFIGURED: bool = true;").unwrap();
    writeln!(
        source,
        "pub const ADAPTER: &str = {:?};",
        benchmark.model.adapter()
    )
    .unwrap();
    writeln!(
        source,
        "pub const EXPECTED_NAME: &str = {:?};",
        benchmark.name
    )
    .unwrap();
    writeln!(
        source,
        "pub const EXPECTED_MODEL: &str = {:?};",
        benchmark.model.name()
    )
    .unwrap();
    writeln!(
        source,
        "pub const PREPARE_OPERATION_FLAGS: u64 = {};",
        benchmark.model.prepare_operation_flags()
    )
    .unwrap();
    writeln!(
        source,
        "pub const EXPECTED_PATTERN: &str = {:?};",
        benchmark.pattern()
    )
    .unwrap();
    writeln!(
        source,
        "pub const EXPECTED_UNICODE: bool = {};",
        benchmark.unicode
    )
    .unwrap();
    writeln!(
        source,
        "pub const EXPECTED_CASE_INSENSITIVE: bool = {};",
        benchmark.case_insensitive
    )
    .unwrap();
    writeln!(source, "pub const TARGET_ARCH: &str = {architecture:?};").unwrap();
    writeln!(source, "pub const TARGET_OS: &str = {operating_system:?};").unwrap();
    writeln!(source, "pub const FEATURE_BITS: u64 = {feature_bits};").unwrap();
    writeln!(source, "pub const SOURCE_COMMIT: &str = {source_commit:?};").unwrap();
    writeln!(source, "pub const SOURCE_TREE: &str = {source_tree:?};").unwrap();
    writeln!(source, "pub const PROGRAM_LEN: usize = {program_len};").unwrap();
    writeln!(
        source,
        "pub const PROGRAM_SYMBOL: &str = {program_symbol:?};"
    )
    .unwrap();
    writeln!(
        source,
        "pub const REDUCER_SYMBOL: &str = {reducer_symbol:?};"
    )
    .unwrap();
    writeln!(
        source,
        "pub const REQUIRED_RUNTIME_SYMBOLS: &str = {runtime_symbols:?};"
    )
    .unwrap();
    writeln!(
        source,
        "pub const ENGINE: &str = {:?};",
        format!("{:?}", receipt.engine)
    )
    .unwrap();
    writeln!(
        source,
        "pub const AGGREGATE_STRATEGY: &str = {:?};",
        format!("{:?}", receipt.prepared_aggregate_strategy)
    )
    .unwrap();
    writeln!(
        source,
        "pub const COMPILER_VERSION: u32 = {};",
        receipt.compiler_version
    )
    .unwrap();
    writeln!(
        source,
        "pub const OPTIMIZER_VERSION: u32 = {};",
        receipt.optimizer_version
    )
    .unwrap();
    writeln!(
        source,
        "pub const PROGRAM_SHA256: [u8; 32] = {:?};",
        receipt.program_sha256
    )
    .unwrap();
    writeln!(
        source,
        "pub const OBJECT_SHA256: [u8; 32] = {:?};",
        receipt.object_sha256
    )
    .unwrap();
    writeln!(
        source,
        "pub static OBJECT_BYTES: &[u8] = include_bytes!({:?});",
        object_path.display().to_string()
    )
    .unwrap();
    source.push_str("unsafe extern \"C\" {\n");
    writeln!(source, "    #[link_name = {program_symbol:?}]").unwrap();
    source.push_str("    static LINKED_PROGRAM_START: u8;\n");
    writeln!(source, "    #[link_name = {reducer_symbol:?}]").unwrap();
    source.push_str(
        "    fn LINKED_REDUCER(handle: fre_aot_regex_runtime::FreAotRegexExclusiveHandleV1, haystack: *const u8, haystack_len: usize, value_out: *mut u64) -> u32;\n}\n",
    );
    source.push_str(
        "pub unsafe fn program_ptr() -> *const u8 { unsafe { &raw const LINKED_PROGRAM_START } }\n",
    );
    source.push_str(
        "pub unsafe fn reduce(handle: fre_aot_regex_runtime::FreAotRegexExclusiveHandleV1, haystack: *const u8, haystack_len: usize, value_out: *mut u64) -> u32 {\n    unsafe { LINKED_REDUCER(handle, haystack, haystack_len, value_out) }\n}\n",
    );
    source
}

fn stub_source() -> &'static str {
    r#"pub const CONFIGURED: bool = false;
pub const ADAPTER: &str = "general-aot-unconfigured";
pub const EXPECTED_NAME: &str = "";
pub const EXPECTED_MODEL: &str = "";
pub const PREPARE_OPERATION_FLAGS: u64 = 0;
pub const EXPECTED_PATTERN: &str = "";
pub const EXPECTED_UNICODE: bool = false;
pub const EXPECTED_CASE_INSENSITIVE: bool = false;
pub const TARGET_ARCH: &str = "";
pub const TARGET_OS: &str = "";
pub const FEATURE_BITS: u64 = 0;
pub const SOURCE_COMMIT: &str = "unconfigured";
pub const SOURCE_TREE: &str = "unconfigured";
pub const PROGRAM_LEN: usize = 0;
pub const PROGRAM_SYMBOL: &str = "";
pub const REDUCER_SYMBOL: &str = "";
pub const REQUIRED_RUNTIME_SYMBOLS: &str = "";
pub const ENGINE: &str = "";
pub const AGGREGATE_STRATEGY: &str = "";
pub const COMPILER_VERSION: u32 = 0;
pub const OPTIMIZER_VERSION: u32 = 0;
pub const PROGRAM_SHA256: [u8; 32] = [0; 32];
pub const OBJECT_SHA256: [u8; 32] = [0; 32];
pub static OBJECT_BYTES: &[u8] = &[];
pub unsafe fn program_ptr() -> *const u8 { core::ptr::null() }
pub unsafe fn reduce(
    _handle: fre_aot_regex_runtime::FreAotRegexExclusiveHandleV1,
    _haystack: *const u8,
    _haystack_len: usize,
    _value_out: *mut u64,
) -> u32 { 2 }
"#
}
