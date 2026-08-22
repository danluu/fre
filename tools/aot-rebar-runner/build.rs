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
    if benchmark.model == shared::Model::RegexRedux {
        let mut components = Vec::with_capacity(shared::REGEX_REDUX_COMPONENTS);
        let mut object_paths = Vec::with_capacity(shared::REGEX_REDUX_COMPONENTS);
        for component in 0..shared::REGEX_REDUX_COMPONENTS {
            let compiled = shared::compile_regex_redux_component(component, target)
                .expect("compile fixed public Rebar regex-redux component");
            let component_path = output.join(format!("aot-rebar-regex-redux-{component:02}.o"));
            fs::write(&component_path, compiled.object())
                .expect("write linked regex-redux component object");
            components.push(compiled);
            object_paths.push(component_path);
        }
        fs::write(&object_path, []).expect("write unused scalar object sentinel");
        fs::write(
            &generated_path,
            configured_regex_redux_source(
                &benchmark,
                &components,
                &object_paths,
                &architecture,
                &operating_system,
                feature_bits,
                &source_commit,
                &source_tree,
            ),
        )
        .expect("write linked regex-redux bindings");
        for component_path in object_paths {
            println!(
                "cargo:rustc-link-arg-bin=fre-aot-rebar-runner={}",
                component_path.display()
            );
        }
        return;
    }
    if benchmark.uses_uniform_capture_bridge() {
        match shared::try_compile_uniform_capture_bridge(&benchmark, target)
            .expect("compile helper-free public Rebar uniform-capture bridge")
        {
            shared::UniformCaptureBridgeDisposition::Proven(bridge) => {
                let mut object_paths = Vec::new();
                object_paths
                    .try_reserve_exact(bridge.rows.artifacts.len())
                    .expect("reserve uniform-capture object paths");
                for (index, artifact) in bridge.rows.artifacts.iter().enumerate() {
                    let row_path = output.join(format!("aot-rebar-capture-row-{index}.o"));
                    fs::write(&row_path, artifact.compiled.object())
                        .expect("write linked uniform-capture selector object");
                    object_paths.push(row_path);
                }
                fs::write(&object_path, []).expect("write unused scalar object sentinel");
                fs::write(
                    &generated_path,
                    configured_native_row_source(
                        &benchmark,
                        &bridge.rows,
                        Some(&bridge.source_receipts),
                        &architecture,
                        &operating_system,
                        feature_bits,
                        &source_commit,
                        &source_tree,
                    ),
                )
                .expect("write linked uniform-capture bindings");
                for row_path in object_paths {
                    println!(
                        "cargo:rustc-link-arg-bin=fre-aot-rebar-runner={}",
                        row_path.display()
                    );
                }
            }
            shared::UniformCaptureBridgeDisposition::Declined { .. } => {
                let bridge = shared::compile_strict_capture_bridge(&benchmark, target)
                    .expect("compile exact single-pattern helper-free capture route");
                fs::write(&object_path, bridge.artifact.object())
                    .expect("write linked strict capture object");
                fs::write(
                    &generated_path,
                    configured_strict_capture_source(
                        &benchmark,
                        &bridge,
                        &architecture,
                        &operating_system,
                        feature_bits,
                        &source_commit,
                        &source_tree,
                    ),
                )
                .expect("write linked strict capture bindings");
                println!(
                    "cargo:rustc-link-arg-bin=fre-aot-rebar-runner={}",
                    object_path.display()
                );
            }
        }
        return;
    }
    if benchmark.uses_native_row_bridge() {
        let bridge = shared::compile_native_row_bridge(&benchmark, target)
            .expect("compile helper-free public Rebar native-row bridge");
        let mut object_paths = Vec::new();
        object_paths
            .try_reserve_exact(bridge.artifacts.len())
            .expect("reserve native-row object paths");
        for (index, artifact) in bridge.artifacts.iter().enumerate() {
            let row_path = output.join(format!("aot-rebar-row-{index}.o"));
            fs::write(&row_path, artifact.compiled.object())
                .expect("write linked general AOT native-row object");
            object_paths.push(row_path);
        }
        fs::write(
            &generated_path,
            configured_native_row_source(
                &benchmark,
                &bridge,
                None,
                &architecture,
                &operating_system,
                feature_bits,
                &source_commit,
                &source_tree,
            ),
        )
        .expect("write linked general AOT native-row bindings");
        for row_path in object_paths {
            println!(
                "cargo:rustc-link-arg-bin=fre-aot-rebar-runner={}",
                row_path.display()
            );
        }
        return;
    }
    let compiled =
        shared::compile_benchmark(&benchmark, target).expect("compile public Rebar build artifact");
    let (program_symbol, program_len) = compiled
        .module()
        .required_runtime_program()
        .expect("prepared reducer publishes its exact runtime program");
    let entry_symbol = compiled.module().entry_symbol();
    let span_fill_symbol = compiled.module().prepared_span_fill_symbol();
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
        shared::Model::CountCaptures | shared::Model::GrepCaptures => {
            unreachable!("capture models use the paired uniform-capture build branch")
        }
        shared::Model::RegexRedux => unreachable!("regex-redux uses the composite build branch"),
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
            entry_symbol,
            span_fill_symbol,
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
    entry_symbol: &str,
    span_fill_symbol: Option<&str>,
    reducer_symbol: &str,
    architecture: &str,
    operating_system: &str,
    feature_bits: u64,
    source_commit: &str,
    source_tree: &str,
) -> String {
    let receipt = compiled.receipt();
    assert_eq!(
        receipt.required_prepare_capabilities,
        compiled.module().required_prepare_capabilities(),
        "compiler receipt and linked module disagree on prepare capabilities"
    );
    let required_prepare_capabilities = receipt.required_prepare_capabilities;
    assert!(
        required_prepare_capabilities == 0
            || matches!(
                benchmark.model,
                shared::Model::Compile | shared::Model::Count | shared::Model::SpanSum
            ),
        "required Ordered-NFA capability is not legal for this operation model"
    );
    let prepare_config_version = if required_prepare_capabilities == 0 {
        2
    } else {
        3
    };
    let prepared_bulk_strategy = format!("{:?}", compiled.module().prepared_bulk_strategy());
    let span_iteration_strategy = if benchmark.model != shared::Model::SpanSum {
        "not-applicable".to_owned()
    } else if span_fill_symbol.is_some() {
        format!("linked-prepared-span-fill-64::{prepared_bulk_strategy}")
    } else {
        "linked-direct-entry-loop".to_owned()
    };
    let grep_iteration_strategy = if benchmark.model == shared::Model::GrepCount {
        "linked-per-line-direct-entry".to_owned()
    } else {
        "not-applicable".to_owned()
    };
    let aggregate_strategy = if benchmark.model == shared::Model::GrepCount {
        grep_iteration_strategy.clone()
    } else {
        format!("{:?}", receipt.prepared_aggregate_strategy)
    };
    let runtime_symbols = compiled
        .module()
        .required_runtime_symbols()
        .collect::<Vec<_>>()
        .join(",");
    let mut source = String::new();
    writeln!(source, "pub const CONFIGURED: bool = true;").unwrap();
    writeln!(source, "pub const NATIVE_ROW_BRIDGE: bool = false;").unwrap();
    writeln!(source, "pub const UNIFORM_CAPTURE_BRIDGE: bool = false;").unwrap();
    writeln!(
        source,
        "pub const ADAPTER: &str = {:?};",
        benchmark
            .model
            .adapter_for_required_capabilities(required_prepare_capabilities)
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
        "pub const PREPARE_CONFIG_VERSION: u32 = {prepare_config_version};"
    )
    .unwrap();
    writeln!(
        source,
        "pub const REQUIRED_PREPARE_CAPABILITIES: u64 = {required_prepare_capabilities};"
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
        "pub const EXPECTED_PATTERNS: &[&str] = &[{:?}];",
        benchmark.pattern()
    )
    .unwrap();
    writeln!(source, "pub const SOURCE_PATTERN_COUNT: usize = 1;").unwrap();
    writeln!(source, "pub const ROW_ARTIFACT_COUNT: usize = 1;").unwrap();
    writeln!(
        source,
        "pub const ROW_TOTAL_OBJECT_BYTES: usize = {};",
        compiled.object().len()
    )
    .unwrap();
    writeln!(source, "pub const SOURCE_TO_ARTIFACT: &[usize] = &[0];").unwrap();
    writeln!(
        source,
        "pub const ROW_FIRST_SOURCE_ORDINALS: &[usize] = &[0];"
    )
    .unwrap();
    writeln!(
        source,
        "pub const ROW_ENTRY_SYMBOLS: &[&str] = &[{entry_symbol:?}];"
    )
    .unwrap();
    writeln!(
        source,
        "pub const ROW_AUTOMATON_SHA256: &[[u8; 32]] = &[{:?}];",
        receipt.automaton_sha256
    )
    .unwrap();
    writeln!(
        source,
        "pub const ROW_PROGRAM_SHA256: &[[u8; 32]] = &[{:?}];",
        receipt.program_sha256
    )
    .unwrap();
    writeln!(
        source,
        "pub const ROW_OBJECT_SHA256: &[[u8; 32]] = &[{:?}];",
        receipt.object_sha256
    )
    .unwrap();
    source.push_str("pub const UNIFORM_CAPTURE_ALGORITHM_VERSION: u32 = 0;\n");
    source.push_str("pub const UNIFORM_CAPTURE_ACCOUNTING_VERSION: u32 = 0;\n");
    source.push_str("pub const ROW_PARTICIPATING_GROUPS: &[u64] = &[];\n");
    source.push_str("pub const SOURCE_PARTICIPATING_GROUPS: &[u64] = &[];\n");
    source.push_str("pub const SOURCE_MINIMUM_MATCH_BYTES: &[usize] = &[];\n");
    source.push_str("pub const SOURCE_CANONICAL_CAPTURE_ANNOTATIONS: &[usize] = &[];\n");
    source.push_str("pub const SOURCE_PROOF_WORK: &[u64] = &[];\n");
    source.push_str("pub const SOURCE_PROOF_PEAK_STACK_ITEMS: &[usize] = &[];\n");
    source.push_str("pub const SOURCE_SELECTOR_AUTOMATON_SHA256: &[[u8; 32]] = &[];\n");
    source.push_str("pub const SOURCE_SELECTOR_PROGRAM_SHA256: &[[u8; 32]] = &[];\n");
    source.push_str("pub const SOURCE_SELECTOR_OBJECT_SHA256: &[[u8; 32]] = &[];\n");
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
    writeln!(source, "pub const ENTRY_SYMBOL: &str = {entry_symbol:?};").unwrap();
    writeln!(
        source,
        "pub const SPAN_FILL_SYMBOL: &str = {:?};",
        span_fill_symbol.unwrap_or("")
    )
    .unwrap();
    writeln!(
        source,
        "pub const HAS_SPAN_FILL: bool = {};",
        span_fill_symbol.is_some()
    )
    .unwrap();
    writeln!(
        source,
        "pub const SPAN_ITERATION_STRATEGY: &str = {:?};",
        span_iteration_strategy
    )
    .unwrap();
    writeln!(
        source,
        "pub const GREP_ITERATION_STRATEGY: &str = {:?};",
        grep_iteration_strategy
    )
    .unwrap();
    writeln!(
        source,
        "pub const PREPARED_BULK_STRATEGY: &str = {prepared_bulk_strategy:?};"
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
        aggregate_strategy
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
    source.push_str("pub const REGEX_REDUX_COMPONENT_COUNT: usize = 0;\n");
    source.push_str("pub const REGEX_REDUX_ENTRY_SYMBOLS: &[&str] = &[];\n");
    source.push_str("pub const REGEX_REDUX_RUNTIME_SYMBOLS: &[&str] = &[];\n");
    source.push_str("pub const REGEX_REDUX_NATIVE: &[bool] = &[];\n");
    source.push_str("pub const REGEX_REDUX_PROGRAM_SHA256: &[[u8; 32]] = &[];\n");
    source.push_str("pub const REGEX_REDUX_OBJECT_SHA256: &[[u8; 32]] = &[];\n");
    writeln!(
        source,
        "pub static OBJECT_BYTES: &[u8] = include_bytes!({:?});",
        object_path.display().to_string()
    )
    .unwrap();
    source.push_str("unsafe extern \"C\" {\n");
    writeln!(source, "    #[link_name = {program_symbol:?}]").unwrap();
    source.push_str("    static LINKED_PROGRAM_START: u8;\n");
    writeln!(source, "    #[link_name = {entry_symbol:?}]").unwrap();
    source.push_str(
        "    fn LINKED_ENTRY(haystack: *const u8, haystack_len: usize, window_start: usize, window_end: usize, result_out: *mut fre_aot_regex_runtime::FreAotRegexResultV1) -> u32;\n",
    );
    writeln!(source, "    #[link_name = {reducer_symbol:?}]").unwrap();
    source.push_str(
        "    fn LINKED_REDUCER(handle: fre_aot_regex_runtime::FreAotRegexExclusiveHandleV1, haystack: *const u8, haystack_len: usize, value_out: *mut u64) -> u32;\n",
    );
    if let Some(span_fill_symbol) = span_fill_symbol {
        writeln!(source, "    #[link_name = {span_fill_symbol:?}]").unwrap();
        source.push_str(
            "    fn LINKED_SPAN_FILL(handle: fre_aot_regex_runtime::FreAotRegexExclusiveHandleV1, haystack: *const u8, haystack_len: usize, state: *mut fre_aot_regex_runtime::FreAotRegexIterStateV1, results: *mut fre_aot_regex_runtime::FreAotRegexResultV1, capacity: usize, written_out: *mut usize) -> u32;\n",
        );
    }
    source.push_str("}\n");
    source.push_str(
        "pub unsafe fn program_ptr() -> *const u8 { unsafe { &raw const LINKED_PROGRAM_START } }\n",
    );
    source.push_str(
        "pub unsafe fn reduce(handle: fre_aot_regex_runtime::FreAotRegexExclusiveHandleV1, haystack: *const u8, haystack_len: usize, value_out: *mut u64) -> u32 {\n    unsafe { LINKED_REDUCER(handle, haystack, haystack_len, value_out) }\n}\n",
    );
    source.push_str(
        "pub unsafe fn search(haystack: *const u8, haystack_len: usize, window_start: usize, window_end: usize, result_out: *mut fre_aot_regex_runtime::FreAotRegexResultV1) -> u32 {\n    unsafe { LINKED_ENTRY(haystack, haystack_len, window_start, window_end, result_out) }\n}\n",
    );
    source.push_str(
        "pub unsafe fn search_row(row: usize, haystack: *const u8, haystack_len: usize, window_start: usize, window_end: usize, result_out: *mut fre_aot_regex_runtime::FreAotRegexResultV1) -> u32 {\n    if row != 0 { return fre_aot_regex_runtime::STATUS_INVALID_ARGUMENT; }\n    unsafe { LINKED_ENTRY(haystack, haystack_len, window_start, window_end, result_out) }\n}\n",
    );
    if span_fill_symbol.is_some() {
        source.push_str(
            "pub unsafe fn fill_spans(handle: fre_aot_regex_runtime::FreAotRegexExclusiveHandleV1, haystack: *const u8, haystack_len: usize, state: *mut fre_aot_regex_runtime::FreAotRegexIterStateV1, results: *mut fre_aot_regex_runtime::FreAotRegexResultV1, capacity: usize, written_out: *mut usize) -> u32 {\n    unsafe { LINKED_SPAN_FILL(handle, haystack, haystack_len, state, results, capacity, written_out) }\n}\n",
        );
    } else {
        source.push_str(
            "pub unsafe fn fill_spans(_handle: fre_aot_regex_runtime::FreAotRegexExclusiveHandleV1, _haystack: *const u8, _haystack_len: usize, _state: *mut fre_aot_regex_runtime::FreAotRegexIterStateV1, _results: *mut fre_aot_regex_runtime::FreAotRegexResultV1, _capacity: usize, _written_out: *mut usize) -> u32 { fre_aot_regex_runtime::STATUS_INVALID_ARGUMENT }\n",
        );
    }
    source.push_str(
        "pub unsafe fn regex_redux_search(_component: usize, _haystack: *const u8, _haystack_len: usize, _window_start: usize, _window_end: usize, _result_out: *mut fre_aot_regex_runtime::FreAotRegexResultV1) -> u32 { fre_aot_regex_runtime::STATUS_INVALID_ARGUMENT }\n",
    );
    push_empty_strict_capture_bindings(&mut source);
    source
}

#[allow(
    clippy::too_many_arguments,
    reason = "the generated composite binding closes every source, target and object identity"
)]
fn configured_regex_redux_source(
    benchmark: &shared::Benchmark,
    components: &[fre_aot_regex::CompiledRegex],
    object_paths: &[PathBuf],
    architecture: &str,
    operating_system: &str,
    feature_bits: u64,
    source_commit: &str,
    source_tree: &str,
) -> String {
    assert_eq!(benchmark.model, shared::Model::RegexRedux);
    assert!(benchmark.patterns.is_empty());
    assert!(!benchmark.unicode && !benchmark.case_insensitive);
    assert_eq!(components.len(), shared::REGEX_REDUX_COMPONENTS);
    assert_eq!(object_paths.len(), components.len());

    let first = components
        .first()
        .expect("regex-redux has fixed components");
    let compiler_version = first.receipt().compiler_version;
    let optimizer_version = first.receipt().optimizer_version;
    let mut entry_symbols = Vec::with_capacity(components.len());
    let mut runtime_symbols = Vec::with_capacity(components.len());
    let mut program_hashes = Vec::with_capacity(components.len());
    let mut object_hashes = Vec::with_capacity(components.len());
    let mut unique_entries = std::collections::BTreeSet::new();
    for (component, compiled) in components.iter().enumerate() {
        let receipt = compiled.receipt();
        assert_eq!(receipt.compiler_version, compiler_version);
        assert_eq!(receipt.optimizer_version, optimizer_version);
        assert_eq!(receipt.required_prepare_capabilities, 0);
        assert_eq!(
            compiled.module().prepared_aggregate_exports(),
            fre_aot_regex::PreparedAggregateExports::NONE
        );
        assert!(compiled.module().prepared_count_symbol().is_none());
        assert!(compiled.module().prepared_span_sum_symbol().is_none());
        assert!(compiled.module().prepared_grep_count_symbol().is_none());
        assert!(compiled.module().prepared_span_fill_symbol().is_none());
        assert!(compiled.module().prepared_entry_symbol().is_none());
        assert!(compiled.module().prepared_exists_batch_symbol().is_none());
        assert!(compiled.module().required_runtime_program().is_none());
        assert!(
            !compiled
                .module()
                .symbols()
                .iter()
                .enumerate()
                .any(|(symbol_index, symbol)| {
                    symbol.section.is_none()
                        && compiled
                            .module()
                            .relocations()
                            .iter()
                            .any(|relocation| relocation.symbol == symbol_index)
                }),
            "regex-redux component {component} retains an unresolved relocation target"
        );
        let entry = compiled.module().entry_symbol();
        assert!(
            unique_entries.insert(entry.to_owned()),
            "regex-redux components {component} and an earlier component share one entry symbol"
        );
        entry_symbols.push(entry.to_owned());
        let component_runtime_symbols = compiled
            .module()
            .required_runtime_symbols()
            .collect::<Vec<_>>()
            .join(",");
        assert!(
            component_runtime_symbols.is_empty(),
            "regex-redux component {component} retains semantic runtime helpers: {component_runtime_symbols}"
        );
        runtime_symbols.push(component_runtime_symbols);
        program_hashes.push(receipt.program_sha256);
        object_hashes.push(receipt.object_sha256);
    }

    let mut source = String::new();
    source.push_str("pub const CONFIGURED: bool = true;\n");
    source.push_str("pub const NATIVE_ROW_BRIDGE: bool = false;\n");
    source.push_str("pub const UNIFORM_CAPTURE_BRIDGE: bool = false;\n");
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
    source.push_str("pub const EXPECTED_MODEL: &str = \"regex-redux\";\n");
    source.push_str("pub const PREPARE_OPERATION_FLAGS: u64 = 0;\n");
    source.push_str("pub const PREPARE_CONFIG_VERSION: u32 = 2;\n");
    source.push_str("pub const REQUIRED_PREPARE_CAPABILITIES: u64 = 0;\n");
    source.push_str("pub const EXPECTED_PATTERN: &str = \"\";\n");
    source.push_str("pub const EXPECTED_PATTERNS: &[&str] = &[];\n");
    source.push_str("pub const SOURCE_PATTERN_COUNT: usize = 0;\n");
    source.push_str("pub const ROW_ARTIFACT_COUNT: usize = 0;\n");
    source.push_str("pub const ROW_TOTAL_OBJECT_BYTES: usize = 0;\n");
    source.push_str("pub const SOURCE_TO_ARTIFACT: &[usize] = &[];\n");
    source.push_str("pub const ROW_FIRST_SOURCE_ORDINALS: &[usize] = &[];\n");
    source.push_str("pub const ROW_ENTRY_SYMBOLS: &[&str] = &[];\n");
    source.push_str("pub const ROW_AUTOMATON_SHA256: &[[u8; 32]] = &[];\n");
    source.push_str("pub const ROW_PROGRAM_SHA256: &[[u8; 32]] = &[];\n");
    source.push_str("pub const ROW_OBJECT_SHA256: &[[u8; 32]] = &[];\n");
    source.push_str("pub const UNIFORM_CAPTURE_ALGORITHM_VERSION: u32 = 0;\n");
    source.push_str("pub const UNIFORM_CAPTURE_ACCOUNTING_VERSION: u32 = 0;\n");
    source.push_str("pub const ROW_PARTICIPATING_GROUPS: &[u64] = &[];\n");
    source.push_str("pub const SOURCE_PARTICIPATING_GROUPS: &[u64] = &[];\n");
    source.push_str("pub const SOURCE_MINIMUM_MATCH_BYTES: &[usize] = &[];\n");
    source.push_str("pub const SOURCE_CANONICAL_CAPTURE_ANNOTATIONS: &[usize] = &[];\n");
    source.push_str("pub const SOURCE_PROOF_WORK: &[u64] = &[];\n");
    source.push_str("pub const SOURCE_PROOF_PEAK_STACK_ITEMS: &[usize] = &[];\n");
    source.push_str("pub const SOURCE_SELECTOR_AUTOMATON_SHA256: &[[u8; 32]] = &[];\n");
    source.push_str("pub const SOURCE_SELECTOR_PROGRAM_SHA256: &[[u8; 32]] = &[];\n");
    source.push_str("pub const SOURCE_SELECTOR_OBJECT_SHA256: &[[u8; 32]] = &[];\n");
    source.push_str("pub const EXPECTED_UNICODE: bool = false;\n");
    source.push_str("pub const EXPECTED_CASE_INSENSITIVE: bool = false;\n");
    writeln!(source, "pub const TARGET_ARCH: &str = {architecture:?};").unwrap();
    writeln!(source, "pub const TARGET_OS: &str = {operating_system:?};").unwrap();
    writeln!(source, "pub const FEATURE_BITS: u64 = {feature_bits};").unwrap();
    writeln!(source, "pub const SOURCE_COMMIT: &str = {source_commit:?};").unwrap();
    writeln!(source, "pub const SOURCE_TREE: &str = {source_tree:?};").unwrap();
    source.push_str("pub const PROGRAM_LEN: usize = 0;\n");
    source.push_str("pub const PROGRAM_SYMBOL: &str = \"\";\n");
    source.push_str("pub const REDUCER_SYMBOL: &str = \"\";\n");
    source.push_str("pub const ENTRY_SYMBOL: &str = \"\";\n");
    source.push_str("pub const SPAN_FILL_SYMBOL: &str = \"\";\n");
    source.push_str("pub const HAS_SPAN_FILL: bool = false;\n");
    source.push_str(
        "pub const SPAN_ITERATION_STRATEGY: &str = \"fixed-component-direct-entry-loop\";\n",
    );
    source.push_str("pub const GREP_ITERATION_STRATEGY: &str = \"not-applicable\";\n");
    source.push_str("pub const PREPARED_BULK_STRATEGY: &str = \"None\";\n");
    source.push_str("pub const REQUIRED_RUNTIME_SYMBOLS: &str = \"component-indexed\";\n");
    source.push_str("pub const ENGINE: &str = \"FixedRegexReduxComponents\";\n");
    source.push_str(
        "pub const AGGREGATE_STRATEGY: &str = \"linked-fixed-regex-redux-span-entries\";\n",
    );
    writeln!(
        source,
        "pub const COMPILER_VERSION: u32 = {compiler_version};"
    )
    .unwrap();
    writeln!(
        source,
        "pub const OPTIMIZER_VERSION: u32 = {optimizer_version};"
    )
    .unwrap();
    source.push_str("pub const PROGRAM_SHA256: [u8; 32] = [0; 32];\n");
    source.push_str("pub const OBJECT_SHA256: [u8; 32] = [0; 32];\n");
    writeln!(
        source,
        "pub const REGEX_REDUX_COMPONENT_COUNT: usize = {};",
        components.len()
    )
    .unwrap();
    writeln!(
        source,
        "pub const REGEX_REDUX_ENTRY_SYMBOLS: &[&str] = &{entry_symbols:?};"
    )
    .unwrap();
    writeln!(
        source,
        "pub const REGEX_REDUX_RUNTIME_SYMBOLS: &[&str] = &{runtime_symbols:?};"
    )
    .unwrap();
    writeln!(
        source,
        "pub const REGEX_REDUX_NATIVE: &[bool] = &{:?};",
        vec![true; components.len()]
    )
    .unwrap();
    writeln!(
        source,
        "pub const REGEX_REDUX_PROGRAM_SHA256: &[[u8; 32]] = &{program_hashes:?};"
    )
    .unwrap();
    writeln!(
        source,
        "pub const REGEX_REDUX_OBJECT_SHA256: &[[u8; 32]] = &{object_hashes:?};"
    )
    .unwrap();
    source.push_str("pub static OBJECT_BYTES: &[u8] = &[];\n");

    source.push_str("unsafe extern \"C\" {\n");
    for (component, entry) in entry_symbols.iter().enumerate() {
        writeln!(source, "    #[link_name = {entry:?}]").unwrap();
        writeln!(source, "    fn REGEX_REDUX_ENTRY_{component}(haystack: *const u8, haystack_len: usize, window_start: usize, window_end: usize, result_out: *mut fre_aot_regex_runtime::FreAotRegexResultV1) -> u32;").unwrap();
    }
    source.push_str("}\n");
    source.push_str("pub unsafe fn program_ptr() -> *const u8 { core::ptr::null() }\n");
    source.push_str("pub unsafe fn reduce(_handle: fre_aot_regex_runtime::FreAotRegexExclusiveHandleV1, _haystack: *const u8, _haystack_len: usize, _value_out: *mut u64) -> u32 { fre_aot_regex_runtime::STATUS_INVALID_ARGUMENT }\n");
    source.push_str("pub unsafe fn search(_haystack: *const u8, _haystack_len: usize, _window_start: usize, _window_end: usize, _result_out: *mut fre_aot_regex_runtime::FreAotRegexResultV1) -> u32 { fre_aot_regex_runtime::STATUS_INVALID_ARGUMENT }\n");
    source.push_str("pub unsafe fn search_row(_row: usize, _haystack: *const u8, _haystack_len: usize, _window_start: usize, _window_end: usize, _result_out: *mut fre_aot_regex_runtime::FreAotRegexResultV1) -> u32 { fre_aot_regex_runtime::STATUS_INVALID_ARGUMENT }\n");
    source.push_str("pub unsafe fn fill_spans(_handle: fre_aot_regex_runtime::FreAotRegexExclusiveHandleV1, _haystack: *const u8, _haystack_len: usize, _state: *mut fre_aot_regex_runtime::FreAotRegexIterStateV1, _results: *mut fre_aot_regex_runtime::FreAotRegexResultV1, _capacity: usize, _written_out: *mut usize) -> u32 { fre_aot_regex_runtime::STATUS_INVALID_ARGUMENT }\n");
    source.push_str("pub unsafe fn regex_redux_search(component: usize, haystack: *const u8, haystack_len: usize, window_start: usize, window_end: usize, result_out: *mut fre_aot_regex_runtime::FreAotRegexResultV1) -> u32 {\n    match component {\n");
    for component in 0..components.len() {
        writeln!(source, "        {component} => unsafe {{ REGEX_REDUX_ENTRY_{component}(haystack, haystack_len, window_start, window_end, result_out) }},").unwrap();
    }
    source.push_str("        _ => fre_aot_regex_runtime::STATUS_INVALID_ARGUMENT,\n    }\n}\n");
    push_empty_strict_capture_bindings(&mut source);
    source
}

#[allow(
    clippy::too_many_arguments,
    reason = "the generated strict binding closes the complete capture artifact identity"
)]
fn configured_strict_capture_source(
    benchmark: &shared::Benchmark,
    bridge: &shared::StrictCaptureBridge,
    architecture: &str,
    operating_system: &str,
    feature_bits: u64,
    source_commit: &str,
    source_tree: &str,
) -> String {
    assert!(benchmark.model.is_capture());
    assert_eq!(benchmark.patterns.len(), 1);
    let artifact = &bridge.artifact;
    assert!(artifact.authenticates_receipt());
    assert!(
        artifact
            .module()
            .required_runtime_symbols()
            .next()
            .is_none()
    );
    let receipt = artifact.receipt();
    let next_symbol = artifact.capture_next_symbol();
    let materialize_symbol = artifact.capture_materialize_symbol();
    let selector_symbol = artifact.selector_entry_symbol();
    let adapter = match benchmark.model {
        shared::Model::CountCaptures => "general-aot-native-single-capture-next-count-v1",
        shared::Model::GrepCaptures => "general-aot-native-single-capture-next-grep-v1",
        _ => unreachable!("strict capture source requires a capture model"),
    };
    let grep_strategy = if benchmark.model == shared::Model::GrepCaptures {
        "per-line-native-single-capture-next-v1"
    } else {
        "not-applicable"
    };

    let mut source = String::new();
    source.push_str("pub const CONFIGURED: bool = true;\n");
    source.push_str("pub const NATIVE_ROW_BRIDGE: bool = true;\n");
    source.push_str("pub const UNIFORM_CAPTURE_BRIDGE: bool = false;\n");
    source.push_str("pub const STRICT_CAPTURE_BRIDGE: bool = true;\n");
    writeln!(source, "pub const ADAPTER: &str = {adapter:?};").unwrap();
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
    source.push_str("pub const PREPARE_OPERATION_FLAGS: u64 = 0;\n");
    source.push_str("pub const PREPARE_CONFIG_VERSION: u32 = 0;\n");
    source.push_str("pub const REQUIRED_PREPARE_CAPABILITIES: u64 = 0;\n");
    source.push_str("pub const EXPECTED_PATTERN: &str = \"\";\n");
    writeln!(
        source,
        "pub const EXPECTED_PATTERNS: &[&str] = &{:?};",
        benchmark.patterns
    )
    .unwrap();
    source.push_str("pub const SOURCE_PATTERN_COUNT: usize = 1;\n");
    source.push_str("pub const ROW_ARTIFACT_COUNT: usize = 1;\n");
    writeln!(
        source,
        "pub const ROW_TOTAL_OBJECT_BYTES: usize = {};",
        artifact.object().len()
    )
    .unwrap();
    source.push_str("pub const SOURCE_TO_ARTIFACT: &[usize] = &[0];\n");
    source.push_str("pub const ROW_FIRST_SOURCE_ORDINALS: &[usize] = &[0];\n");
    writeln!(
        source,
        "pub const ROW_ENTRY_SYMBOLS: &[&str] = &[{next_symbol:?}];"
    )
    .unwrap();
    writeln!(
        source,
        "pub const ROW_AUTOMATON_SHA256: &[[u8; 32]] = &[{:?}];",
        receipt.selector_sha256()
    )
    .unwrap();
    writeln!(
        source,
        "pub const ROW_PROGRAM_SHA256: &[[u8; 32]] = &[{:?}];",
        receipt.capture_sha256()
    )
    .unwrap();
    writeln!(
        source,
        "pub const ROW_OBJECT_SHA256: &[[u8; 32]] = &[{:?}];",
        receipt.object_sha256()
    )
    .unwrap();
    source.push_str("pub const UNIFORM_CAPTURE_ALGORITHM_VERSION: u32 = 0;\n");
    source.push_str("pub const UNIFORM_CAPTURE_ACCOUNTING_VERSION: u32 = 0;\n");
    source.push_str("pub const ROW_PARTICIPATING_GROUPS: &[u64] = &[];\n");
    source.push_str("pub const SOURCE_PARTICIPATING_GROUPS: &[u64] = &[];\n");
    source.push_str("pub const SOURCE_MINIMUM_MATCH_BYTES: &[usize] = &[];\n");
    source.push_str("pub const SOURCE_CANONICAL_CAPTURE_ANNOTATIONS: &[usize] = &[];\n");
    source.push_str("pub const SOURCE_PROOF_WORK: &[u64] = &[];\n");
    source.push_str("pub const SOURCE_PROOF_PEAK_STACK_ITEMS: &[usize] = &[];\n");
    source.push_str("pub const SOURCE_SELECTOR_AUTOMATON_SHA256: &[[u8; 32]] = &[];\n");
    source.push_str("pub const SOURCE_SELECTOR_PROGRAM_SHA256: &[[u8; 32]] = &[];\n");
    source.push_str("pub const SOURCE_SELECTOR_OBJECT_SHA256: &[[u8; 32]] = &[];\n");
    writeln!(
        source,
        "pub const STRICT_CAPTURE_GROUP_COUNT: usize = {};",
        receipt.group_count()
    )
    .unwrap();
    writeln!(
        source,
        "pub const STRICT_CAPTURE_CAN_MATCH_EMPTY: bool = {};",
        receipt.can_match_empty()
    )
    .unwrap();
    writeln!(
        source,
        "pub const STRICT_CAPTURE_SOURCE_SHA256: [u8; 32] = {:?};",
        receipt.source_sha256()
    )
    .unwrap();
    writeln!(
        source,
        "pub const STRICT_CAPTURE_SELECTOR_SHA256: [u8; 32] = {:?};",
        receipt.selector_sha256()
    )
    .unwrap();
    writeln!(
        source,
        "pub const STRICT_CAPTURE_CAPTURE_SHA256: [u8; 32] = {:?};",
        receipt.capture_sha256()
    )
    .unwrap();
    writeln!(
        source,
        "pub const STRICT_CAPTURE_PLAN_SHA256: [u8; 32] = {:?};",
        receipt.plan_sha256()
    )
    .unwrap();
    writeln!(
        source,
        "pub const STRICT_CAPTURE_BUNDLE_SHA256: [u8; 32] = {:?};",
        receipt.bundle_sha256()
    )
    .unwrap();
    writeln!(
        source,
        "pub const STRICT_CAPTURE_ARTIFACT_IDENTITY_SHA256: [u8; 32] = {:?};",
        receipt.artifact_identity_sha256()
    )
    .unwrap();
    writeln!(
        source,
        "pub const STRICT_CAPTURE_NEXT_SYMBOL: &str = {next_symbol:?};"
    )
    .unwrap();
    writeln!(
        source,
        "pub const STRICT_CAPTURE_MATERIALIZE_SYMBOL: &str = {materialize_symbol:?};"
    )
    .unwrap();
    writeln!(
        source,
        "pub const STRICT_CAPTURE_SELECTOR_SYMBOL: &str = {selector_symbol:?};"
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
    source.push_str("pub const PROGRAM_LEN: usize = 0;\n");
    source.push_str("pub const PROGRAM_SYMBOL: &str = \"\";\n");
    source.push_str("pub const REDUCER_SYMBOL: &str = \"\";\n");
    writeln!(source, "pub const ENTRY_SYMBOL: &str = {next_symbol:?};").unwrap();
    source.push_str("pub const SPAN_FILL_SYMBOL: &str = \"\";\n");
    source.push_str("pub const HAS_SPAN_FILL: bool = false;\n");
    source.push_str("pub const SPAN_ITERATION_STRATEGY: &str = \"not-applicable\";\n");
    writeln!(
        source,
        "pub const GREP_ITERATION_STRATEGY: &str = {grep_strategy:?};"
    )
    .unwrap();
    source.push_str("pub const PREPARED_BULK_STRATEGY: &str = \"None\";\n");
    source.push_str("pub const REQUIRED_RUNTIME_SYMBOLS: &str = \"\";\n");
    source.push_str("pub const ENGINE: &str = \"NativeOnePassCaptureV1\";\n");
    source.push_str(
        "pub const AGGREGATE_STRATEGY: &str = \"native-single-capture-next-participation-v1\";\n",
    );
    writeln!(
        source,
        "pub const COMPILER_VERSION: u32 = {};",
        fre_aot_regex::COMPILER_VERSION
    )
    .unwrap();
    writeln!(
        source,
        "pub const OPTIMIZER_VERSION: u32 = {};",
        fre_aot_regex::OPTIMIZER_VERSION
    )
    .unwrap();
    writeln!(
        source,
        "pub const PROGRAM_SHA256: [u8; 32] = {:?};",
        receipt.capture_sha256()
    )
    .unwrap();
    writeln!(
        source,
        "pub const OBJECT_SHA256: [u8; 32] = {:?};",
        receipt.object_sha256()
    )
    .unwrap();
    source.push_str("pub const REGEX_REDUX_COMPONENT_COUNT: usize = 0;\n");
    source.push_str("pub const REGEX_REDUX_ENTRY_SYMBOLS: &[&str] = &[];\n");
    source.push_str("pub const REGEX_REDUX_RUNTIME_SYMBOLS: &[&str] = &[];\n");
    source.push_str("pub const REGEX_REDUX_NATIVE: &[bool] = &[];\n");
    source.push_str("pub const REGEX_REDUX_PROGRAM_SHA256: &[[u8; 32]] = &[];\n");
    source.push_str("pub const REGEX_REDUX_OBJECT_SHA256: &[[u8; 32]] = &[];\n");
    source.push_str("pub static OBJECT_BYTES: &[u8] = &[];\n");
    source.push_str("unsafe extern \"C\" {\n");
    writeln!(source, "    #[link_name = {next_symbol:?}]").unwrap();
    source.push_str("    fn LINKED_STRICT_CAPTURE_NEXT(haystack: *const u8, haystack_len: usize, state: *mut fre_aot_regex_runtime::FreAotRegexIterStateV1, slots: *mut fre_aot_regex_runtime::FreAotRegexCaptureSlotV1, slot_count: usize) -> u32;\n");
    source.push_str("}\n");
    source.push_str("pub unsafe fn program_ptr() -> *const u8 { core::ptr::null() }\n");
    source.push_str("pub unsafe fn reduce(_handle: fre_aot_regex_runtime::FreAotRegexExclusiveHandleV1, _haystack: *const u8, _haystack_len: usize, _value_out: *mut u64) -> u32 { fre_aot_regex_runtime::STATUS_INVALID_ARGUMENT }\n");
    source.push_str("pub unsafe fn search(_haystack: *const u8, _haystack_len: usize, _window_start: usize, _window_end: usize, _result_out: *mut fre_aot_regex_runtime::FreAotRegexResultV1) -> u32 { fre_aot_regex_runtime::STATUS_INVALID_ARGUMENT }\n");
    source.push_str("pub unsafe fn search_row(_row: usize, _haystack: *const u8, _haystack_len: usize, _window_start: usize, _window_end: usize, _result_out: *mut fre_aot_regex_runtime::FreAotRegexResultV1) -> u32 { fre_aot_regex_runtime::STATUS_INVALID_ARGUMENT }\n");
    source.push_str("pub unsafe fn fill_spans(_handle: fre_aot_regex_runtime::FreAotRegexExclusiveHandleV1, _haystack: *const u8, _haystack_len: usize, _state: *mut fre_aot_regex_runtime::FreAotRegexIterStateV1, _results: *mut fre_aot_regex_runtime::FreAotRegexResultV1, _capacity: usize, _written_out: *mut usize) -> u32 { fre_aot_regex_runtime::STATUS_INVALID_ARGUMENT }\n");
    source.push_str("pub unsafe fn regex_redux_search(_component: usize, _haystack: *const u8, _haystack_len: usize, _window_start: usize, _window_end: usize, _result_out: *mut fre_aot_regex_runtime::FreAotRegexResultV1) -> u32 { fre_aot_regex_runtime::STATUS_INVALID_ARGUMENT }\n");
    source.push_str("pub unsafe fn capture_next(haystack: *const u8, haystack_len: usize, state: *mut fre_aot_regex_runtime::FreAotRegexIterStateV1, slots: *mut fre_aot_regex_runtime::FreAotRegexCaptureSlotV1, slot_count: usize) -> u32 { unsafe { LINKED_STRICT_CAPTURE_NEXT(haystack, haystack_len, state, slots, slot_count) } }\n");
    source
}

#[allow(
    clippy::too_many_arguments,
    reason = "the generated bridge binds every row and source identity component explicitly"
)]
fn configured_native_row_source(
    benchmark: &shared::Benchmark,
    bridge: &shared::NativeRowBridge,
    uniform_capture_receipts: Option<&[fre_aot_regex::UniformCaptureCompileReceipt]>,
    architecture: &str,
    operating_system: &str,
    feature_bits: u64,
    source_commit: &str,
    source_tree: &str,
) -> String {
    assert!(benchmark.uses_native_row_bridge() || benchmark.uses_uniform_capture_bridge());
    assert!(!bridge.artifacts.is_empty());
    assert_eq!(bridge.source_to_artifact.len(), benchmark.patterns.len());
    assert_eq!(
        uniform_capture_receipts.is_some(),
        benchmark.uses_uniform_capture_bridge()
    );
    if let Some(receipts) = uniform_capture_receipts {
        assert_eq!(receipts.len(), benchmark.patterns.len());
    }
    assert_eq!(
        bridge.total_object_bytes,
        bridge
            .artifacts
            .iter()
            .map(|artifact| artifact.compiled.object().len())
            .sum::<usize>()
    );

    let first = &bridge.artifacts[0].compiled;
    let compiler_version = first.receipt().compiler_version;
    let optimizer_version = first.receipt().optimizer_version;
    let first_program_sha256 = first.receipt().program_sha256;
    let first_object_sha256 = first.receipt().object_sha256;
    for artifact in &bridge.artifacts {
        let compiled = &artifact.compiled;
        assert_eq!(compiled.receipt().compiler_version, compiler_version);
        assert_eq!(compiled.receipt().optimizer_version, optimizer_version);
        assert_eq!(compiled.receipt().target, first.receipt().target);
        assert_eq!(
            compiled.receipt().output,
            fre_aot_regex::OutputContract::Span
        );
        assert!(!compiled.receipt().runtime_helper_required);
        assert!(
            compiled
                .module()
                .required_runtime_symbols()
                .next()
                .is_none()
        );
        assert!(
            !compiled
                .module()
                .symbols()
                .iter()
                .enumerate()
                .any(|(index, symbol)| {
                    symbol.section.is_none()
                        && compiled
                            .module()
                            .relocations()
                            .iter()
                            .any(|relocation| relocation.symbol == index)
                })
        );
        assert!(compiled.module().prepared_entry_symbol().is_none());
        assert!(compiled.module().required_runtime_program().is_none());
    }

    let adapter = match benchmark.model {
        shared::Model::Count => "general-aot-native-row-bridge-count-v1",
        shared::Model::SpanSum => "general-aot-native-row-bridge-count-spans-v1",
        shared::Model::GrepCount => "general-aot-native-row-bridge-grep-v1",
        shared::Model::CountCaptures => {
            "general-aot-uniform-capture-native-row-count-adapter-loop-v1"
        }
        shared::Model::GrepCaptures => {
            "general-aot-uniform-capture-native-row-grep-adapter-loop-v1"
        }
        shared::Model::Compile | shared::Model::RegexRedux => {
            unreachable!("parser excludes this multi-pattern model")
        }
    };
    let uniform_capture = uniform_capture_receipts.is_some();
    let aggregate_strategy = if uniform_capture {
        "native-row-static-uniform-capture-multiplier-v1"
    } else if benchmark.model == shared::Model::GrepCount {
        "per-line-native-independent-span-row-exists-v1"
    } else {
        "native-independent-span-row-selector-v1"
    };
    let span_iteration_strategy = if benchmark.model == shared::Model::SpanSum {
        aggregate_strategy
    } else {
        "not-applicable"
    };
    let grep_iteration_strategy = match benchmark.model {
        shared::Model::GrepCount => "per-line-native-independent-span-row-exists-v1",
        shared::Model::GrepCaptures => "per-line-native-row-static-uniform-capture-v1",
        _ => "not-applicable",
    };
    let first_source_ordinals = bridge
        .artifacts
        .iter()
        .map(|artifact| artifact.first_source_ordinal)
        .collect::<Vec<_>>();
    let entry_symbols = bridge
        .artifacts
        .iter()
        .map(|artifact| artifact.compiled.module().entry_symbol())
        .collect::<Vec<_>>();
    let engines = bridge
        .artifacts
        .iter()
        .map(|artifact| format!("{:?}", artifact.compiled.receipt().engine))
        .collect::<Vec<_>>();
    let row_program_hashes = bridge
        .artifacts
        .iter()
        .map(|artifact| artifact.compiled.receipt().program_sha256)
        .collect::<Vec<_>>();
    let row_automaton_hashes = bridge
        .artifacts
        .iter()
        .map(|artifact| artifact.compiled.receipt().automaton_sha256)
        .collect::<Vec<_>>();
    let row_object_hashes = bridge
        .artifacts
        .iter()
        .map(|artifact| artifact.compiled.receipt().object_sha256)
        .collect::<Vec<_>>();
    let mut proof_algorithm_version = 0_u32;
    let mut proof_accounting_version = 0_u32;
    let mut source_participating_groups = Vec::<u64>::new();
    let mut source_minimum_match_bytes = Vec::<usize>::new();
    let mut source_canonical_capture_annotations = Vec::<usize>::new();
    let mut source_proof_work = Vec::<u64>::new();
    let mut source_proof_peak_stack_items = Vec::<usize>::new();
    let mut source_selector_automaton_hashes = Vec::<[u8; 32]>::new();
    let mut source_selector_program_hashes = Vec::<[u8; 32]>::new();
    let mut source_selector_object_hashes = Vec::<[u8; 32]>::new();
    if let Some(receipts) = uniform_capture_receipts {
        let first_identity = receipts[0].participation().identity();
        proof_algorithm_version = first_identity.algorithm_version();
        proof_accounting_version = first_identity.accounting_version();
        for receipt in receipts {
            let participation = receipt.participation();
            assert_eq!(participation.identity(), first_identity);
            source_participating_groups.push(
                u64::try_from(participation.participating_groups_per_match().get())
                    .expect("capture multiplier fits u64"),
            );
            source_minimum_match_bytes.push(participation.minimum_match_bytes().get());
            source_canonical_capture_annotations
                .push(participation.canonical_capture_annotations());
            source_proof_work.push(participation.work());
            source_proof_peak_stack_items.push(participation.peak_stack_items());
            source_selector_automaton_hashes.push(receipt.selector_automaton_sha256());
            source_selector_program_hashes.push(receipt.selector_program_sha256());
            source_selector_object_hashes.push(receipt.selector_object_sha256());
        }
    }
    let row_participating_groups = if uniform_capture_receipts.is_some() {
        first_source_ordinals
            .iter()
            .map(|&source| source_participating_groups[source])
            .collect::<Vec<_>>()
    } else {
        Vec::new()
    };

    let mut source = String::new();
    writeln!(source, "pub const CONFIGURED: bool = true;").unwrap();
    writeln!(source, "pub const NATIVE_ROW_BRIDGE: bool = true;").unwrap();
    writeln!(
        source,
        "pub const UNIFORM_CAPTURE_BRIDGE: bool = {uniform_capture};"
    )
    .unwrap();
    writeln!(source, "pub const ADAPTER: &str = {adapter:?};").unwrap();
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
    writeln!(source, "pub const PREPARE_OPERATION_FLAGS: u64 = 0;").unwrap();
    writeln!(source, "pub const PREPARE_CONFIG_VERSION: u32 = 0;").unwrap();
    writeln!(source, "pub const REQUIRED_PREPARE_CAPABILITIES: u64 = 0;").unwrap();
    writeln!(source, "pub const EXPECTED_PATTERN: &str = \"\";").unwrap();
    writeln!(
        source,
        "pub const EXPECTED_PATTERNS: &[&str] = &{:?};",
        benchmark.patterns
    )
    .unwrap();
    writeln!(
        source,
        "pub const SOURCE_PATTERN_COUNT: usize = {};",
        benchmark.patterns.len()
    )
    .unwrap();
    writeln!(
        source,
        "pub const ROW_ARTIFACT_COUNT: usize = {};",
        bridge.artifacts.len()
    )
    .unwrap();
    writeln!(
        source,
        "pub const ROW_TOTAL_OBJECT_BYTES: usize = {};",
        bridge.total_object_bytes
    )
    .unwrap();
    writeln!(
        source,
        "pub const SOURCE_TO_ARTIFACT: &[usize] = &{:?};",
        bridge.source_to_artifact
    )
    .unwrap();
    writeln!(
        source,
        "pub const ROW_FIRST_SOURCE_ORDINALS: &[usize] = &{first_source_ordinals:?};"
    )
    .unwrap();
    writeln!(
        source,
        "pub const ROW_ENTRY_SYMBOLS: &[&str] = &{entry_symbols:?};"
    )
    .unwrap();
    writeln!(
        source,
        "pub const ROW_AUTOMATON_SHA256: &[[u8; 32]] = &{row_automaton_hashes:?};"
    )
    .unwrap();
    writeln!(
        source,
        "pub const ROW_PROGRAM_SHA256: &[[u8; 32]] = &{row_program_hashes:?};"
    )
    .unwrap();
    writeln!(
        source,
        "pub const ROW_OBJECT_SHA256: &[[u8; 32]] = &{row_object_hashes:?};"
    )
    .unwrap();
    writeln!(
        source,
        "pub const UNIFORM_CAPTURE_ALGORITHM_VERSION: u32 = {proof_algorithm_version};"
    )
    .unwrap();
    writeln!(
        source,
        "pub const UNIFORM_CAPTURE_ACCOUNTING_VERSION: u32 = {proof_accounting_version};"
    )
    .unwrap();
    writeln!(
        source,
        "pub const ROW_PARTICIPATING_GROUPS: &[u64] = &{row_participating_groups:?};"
    )
    .unwrap();
    writeln!(
        source,
        "pub const SOURCE_PARTICIPATING_GROUPS: &[u64] = &{source_participating_groups:?};"
    )
    .unwrap();
    writeln!(
        source,
        "pub const SOURCE_MINIMUM_MATCH_BYTES: &[usize] = &{source_minimum_match_bytes:?};"
    )
    .unwrap();
    writeln!(
        source,
        "pub const SOURCE_CANONICAL_CAPTURE_ANNOTATIONS: &[usize] = &{source_canonical_capture_annotations:?};"
    )
    .unwrap();
    writeln!(
        source,
        "pub const SOURCE_PROOF_WORK: &[u64] = &{source_proof_work:?};"
    )
    .unwrap();
    writeln!(
        source,
        "pub const SOURCE_PROOF_PEAK_STACK_ITEMS: &[usize] = &{source_proof_peak_stack_items:?};"
    )
    .unwrap();
    writeln!(
        source,
        "pub const SOURCE_SELECTOR_AUTOMATON_SHA256: &[[u8; 32]] = &{source_selector_automaton_hashes:?};"
    )
    .unwrap();
    writeln!(
        source,
        "pub const SOURCE_SELECTOR_PROGRAM_SHA256: &[[u8; 32]] = &{source_selector_program_hashes:?};"
    )
    .unwrap();
    writeln!(
        source,
        "pub const SOURCE_SELECTOR_OBJECT_SHA256: &[[u8; 32]] = &{source_selector_object_hashes:?};"
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
    writeln!(source, "pub const PROGRAM_LEN: usize = 0;").unwrap();
    writeln!(source, "pub const PROGRAM_SYMBOL: &str = \"\";").unwrap();
    writeln!(source, "pub const REDUCER_SYMBOL: &str = \"\";").unwrap();
    writeln!(
        source,
        "pub const ENTRY_SYMBOL: &str = \"native-row-table\";"
    )
    .unwrap();
    writeln!(source, "pub const SPAN_FILL_SYMBOL: &str = \"\";").unwrap();
    writeln!(source, "pub const HAS_SPAN_FILL: bool = false;").unwrap();
    writeln!(
        source,
        "pub const SPAN_ITERATION_STRATEGY: &str = {span_iteration_strategy:?};"
    )
    .unwrap();
    writeln!(
        source,
        "pub const GREP_ITERATION_STRATEGY: &str = {grep_iteration_strategy:?};"
    )
    .unwrap();
    writeln!(source, "pub const PREPARED_BULK_STRATEGY: &str = \"None\";").unwrap();
    writeln!(source, "pub const REQUIRED_RUNTIME_SYMBOLS: &str = \"\";").unwrap();
    writeln!(
        source,
        "pub const ENGINE: &str = {:?};",
        format!("IndependentNativeSpanRows({})", engines.join(","))
    )
    .unwrap();
    writeln!(
        source,
        "pub const AGGREGATE_STRATEGY: &str = {aggregate_strategy:?};"
    )
    .unwrap();
    writeln!(
        source,
        "pub const COMPILER_VERSION: u32 = {compiler_version};"
    )
    .unwrap();
    writeln!(
        source,
        "pub const OPTIMIZER_VERSION: u32 = {optimizer_version};"
    )
    .unwrap();
    writeln!(
        source,
        "pub const PROGRAM_SHA256: [u8; 32] = {first_program_sha256:?};"
    )
    .unwrap();
    writeln!(
        source,
        "pub const OBJECT_SHA256: [u8; 32] = {first_object_sha256:?};"
    )
    .unwrap();
    source.push_str("pub const REGEX_REDUX_COMPONENT_COUNT: usize = 0;\n");
    source.push_str("pub const REGEX_REDUX_ENTRY_SYMBOLS: &[&str] = &[];\n");
    source.push_str("pub const REGEX_REDUX_RUNTIME_SYMBOLS: &[&str] = &[];\n");
    source.push_str("pub const REGEX_REDUX_NATIVE: &[bool] = &[];\n");
    source.push_str("pub const REGEX_REDUX_PROGRAM_SHA256: &[[u8; 32]] = &[];\n");
    source.push_str("pub const REGEX_REDUX_OBJECT_SHA256: &[[u8; 32]] = &[];\n");
    writeln!(source, "pub static OBJECT_BYTES: &[u8] = &[];").unwrap();
    source.push_str(
        "pub type LinkedRowSearch = unsafe extern \"C\" fn(*const u8, usize, usize, usize, *mut fre_aot_regex_runtime::FreAotRegexResultV1) -> u32;\n",
    );
    source.push_str("unsafe extern \"C\" {\n");
    for (index, entry_symbol) in entry_symbols.iter().enumerate() {
        writeln!(source, "    #[link_name = {entry_symbol:?}]").unwrap();
        writeln!(source, "    fn LINKED_ROW_ENTRY_{index}(haystack: *const u8, haystack_len: usize, window_start: usize, window_end: usize, result_out: *mut fre_aot_regex_runtime::FreAotRegexResultV1) -> u32;").unwrap();
    }
    source.push_str("}\n");
    source.push_str("pub static LINKED_ROW_SEARCHES: &[LinkedRowSearch] = &[\n");
    for index in 0..entry_symbols.len() {
        writeln!(source, "    LINKED_ROW_ENTRY_{index},").unwrap();
    }
    source.push_str("];\n");
    source.push_str("pub unsafe fn program_ptr() -> *const u8 { core::ptr::null() }\n");
    source.push_str(
        "pub unsafe fn reduce(_handle: fre_aot_regex_runtime::FreAotRegexExclusiveHandleV1, _haystack: *const u8, _haystack_len: usize, _value_out: *mut u64) -> u32 { fre_aot_regex_runtime::STATUS_INVALID_ARGUMENT }\n",
    );
    source.push_str(
        "pub unsafe fn search(_haystack: *const u8, _haystack_len: usize, _window_start: usize, _window_end: usize, _result_out: *mut fre_aot_regex_runtime::FreAotRegexResultV1) -> u32 { fre_aot_regex_runtime::STATUS_INVALID_ARGUMENT }\n",
    );
    source.push_str(
        "pub unsafe fn search_row(row: usize, haystack: *const u8, haystack_len: usize, window_start: usize, window_end: usize, result_out: *mut fre_aot_regex_runtime::FreAotRegexResultV1) -> u32 {\n    let Some(search) = LINKED_ROW_SEARCHES.get(row) else { return fre_aot_regex_runtime::STATUS_INVALID_ARGUMENT; };\n    unsafe { search(haystack, haystack_len, window_start, window_end, result_out) }\n}\n",
    );
    source.push_str(
        "pub unsafe fn fill_spans(_handle: fre_aot_regex_runtime::FreAotRegexExclusiveHandleV1, _haystack: *const u8, _haystack_len: usize, _state: *mut fre_aot_regex_runtime::FreAotRegexIterStateV1, _results: *mut fre_aot_regex_runtime::FreAotRegexResultV1, _capacity: usize, _written_out: *mut usize) -> u32 { fre_aot_regex_runtime::STATUS_INVALID_ARGUMENT }\n",
    );
    source.push_str(
        "pub unsafe fn regex_redux_search(_component: usize, _haystack: *const u8, _haystack_len: usize, _window_start: usize, _window_end: usize, _result_out: *mut fre_aot_regex_runtime::FreAotRegexResultV1) -> u32 { fre_aot_regex_runtime::STATUS_INVALID_ARGUMENT }\n",
    );
    push_empty_strict_capture_bindings(&mut source);
    source
}

fn push_empty_strict_capture_bindings(source: &mut String) {
    source.push_str("pub const STRICT_CAPTURE_BRIDGE: bool = false;\n");
    source.push_str("pub const STRICT_CAPTURE_GROUP_COUNT: usize = 0;\n");
    source.push_str("pub const STRICT_CAPTURE_CAN_MATCH_EMPTY: bool = false;\n");
    source.push_str("pub const STRICT_CAPTURE_SOURCE_SHA256: [u8; 32] = [0; 32];\n");
    source.push_str("pub const STRICT_CAPTURE_SELECTOR_SHA256: [u8; 32] = [0; 32];\n");
    source.push_str("pub const STRICT_CAPTURE_CAPTURE_SHA256: [u8; 32] = [0; 32];\n");
    source.push_str("pub const STRICT_CAPTURE_PLAN_SHA256: [u8; 32] = [0; 32];\n");
    source.push_str("pub const STRICT_CAPTURE_BUNDLE_SHA256: [u8; 32] = [0; 32];\n");
    source.push_str("pub const STRICT_CAPTURE_ARTIFACT_IDENTITY_SHA256: [u8; 32] = [0; 32];\n");
    source.push_str("pub const STRICT_CAPTURE_NEXT_SYMBOL: &str = \"\";\n");
    source.push_str("pub const STRICT_CAPTURE_MATERIALIZE_SYMBOL: &str = \"\";\n");
    source.push_str("pub const STRICT_CAPTURE_SELECTOR_SYMBOL: &str = \"\";\n");
    source.push_str("pub unsafe fn capture_next(_haystack: *const u8, _haystack_len: usize, _state: *mut fre_aot_regex_runtime::FreAotRegexIterStateV1, _slots: *mut fre_aot_regex_runtime::FreAotRegexCaptureSlotV1, _slot_count: usize) -> u32 { fre_aot_regex_runtime::STATUS_INVALID_ARGUMENT }\n");
}

fn stub_source() -> &'static str {
    r#"pub const CONFIGURED: bool = false;
pub const NATIVE_ROW_BRIDGE: bool = false;
pub const UNIFORM_CAPTURE_BRIDGE: bool = false;
pub const STRICT_CAPTURE_BRIDGE: bool = false;
pub const STRICT_CAPTURE_GROUP_COUNT: usize = 0;
pub const STRICT_CAPTURE_CAN_MATCH_EMPTY: bool = false;
pub const STRICT_CAPTURE_SOURCE_SHA256: [u8; 32] = [0; 32];
pub const STRICT_CAPTURE_SELECTOR_SHA256: [u8; 32] = [0; 32];
pub const STRICT_CAPTURE_CAPTURE_SHA256: [u8; 32] = [0; 32];
pub const STRICT_CAPTURE_PLAN_SHA256: [u8; 32] = [0; 32];
pub const STRICT_CAPTURE_BUNDLE_SHA256: [u8; 32] = [0; 32];
pub const STRICT_CAPTURE_ARTIFACT_IDENTITY_SHA256: [u8; 32] = [0; 32];
pub const STRICT_CAPTURE_NEXT_SYMBOL: &str = "";
pub const STRICT_CAPTURE_MATERIALIZE_SYMBOL: &str = "";
pub const STRICT_CAPTURE_SELECTOR_SYMBOL: &str = "";
pub const ADAPTER: &str = "general-aot-unconfigured";
pub const EXPECTED_NAME: &str = "";
pub const EXPECTED_MODEL: &str = "";
pub const PREPARE_OPERATION_FLAGS: u64 = 0;
pub const PREPARE_CONFIG_VERSION: u32 = 2;
pub const REQUIRED_PREPARE_CAPABILITIES: u64 = 0;
pub const EXPECTED_PATTERN: &str = "";
pub const EXPECTED_PATTERNS: &[&str] = &[];
pub const SOURCE_PATTERN_COUNT: usize = 0;
pub const ROW_ARTIFACT_COUNT: usize = 0;
pub const ROW_TOTAL_OBJECT_BYTES: usize = 0;
pub const SOURCE_TO_ARTIFACT: &[usize] = &[];
pub const ROW_FIRST_SOURCE_ORDINALS: &[usize] = &[];
pub const ROW_ENTRY_SYMBOLS: &[&str] = &[];
pub const ROW_AUTOMATON_SHA256: &[[u8; 32]] = &[];
pub const ROW_PROGRAM_SHA256: &[[u8; 32]] = &[];
pub const ROW_OBJECT_SHA256: &[[u8; 32]] = &[];
pub const UNIFORM_CAPTURE_ALGORITHM_VERSION: u32 = 0;
pub const UNIFORM_CAPTURE_ACCOUNTING_VERSION: u32 = 0;
pub const ROW_PARTICIPATING_GROUPS: &[u64] = &[];
pub const SOURCE_PARTICIPATING_GROUPS: &[u64] = &[];
pub const SOURCE_MINIMUM_MATCH_BYTES: &[usize] = &[];
pub const SOURCE_CANONICAL_CAPTURE_ANNOTATIONS: &[usize] = &[];
pub const SOURCE_PROOF_WORK: &[u64] = &[];
pub const SOURCE_PROOF_PEAK_STACK_ITEMS: &[usize] = &[];
pub const SOURCE_SELECTOR_AUTOMATON_SHA256: &[[u8; 32]] = &[];
pub const SOURCE_SELECTOR_PROGRAM_SHA256: &[[u8; 32]] = &[];
pub const SOURCE_SELECTOR_OBJECT_SHA256: &[[u8; 32]] = &[];
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
pub const ENTRY_SYMBOL: &str = "";
pub const SPAN_FILL_SYMBOL: &str = "";
pub const HAS_SPAN_FILL: bool = false;
pub const SPAN_ITERATION_STRATEGY: &str = "unconfigured";
pub const GREP_ITERATION_STRATEGY: &str = "unconfigured";
pub const PREPARED_BULK_STRATEGY: &str = "None";
pub const REQUIRED_RUNTIME_SYMBOLS: &str = "";
pub const ENGINE: &str = "";
pub const AGGREGATE_STRATEGY: &str = "";
pub const COMPILER_VERSION: u32 = 0;
pub const OPTIMIZER_VERSION: u32 = 0;
pub const PROGRAM_SHA256: [u8; 32] = [0; 32];
pub const OBJECT_SHA256: [u8; 32] = [0; 32];
pub const REGEX_REDUX_COMPONENT_COUNT: usize = 0;
pub const REGEX_REDUX_ENTRY_SYMBOLS: &[&str] = &[];
pub const REGEX_REDUX_RUNTIME_SYMBOLS: &[&str] = &[];
pub const REGEX_REDUX_NATIVE: &[bool] = &[];
pub const REGEX_REDUX_PROGRAM_SHA256: &[[u8; 32]] = &[];
pub const REGEX_REDUX_OBJECT_SHA256: &[[u8; 32]] = &[];
pub static OBJECT_BYTES: &[u8] = &[];
pub unsafe fn program_ptr() -> *const u8 { core::ptr::null() }
pub unsafe fn reduce(
    _handle: fre_aot_regex_runtime::FreAotRegexExclusiveHandleV1,
    _haystack: *const u8,
    _haystack_len: usize,
    _value_out: *mut u64,
) -> u32 { 2 }
pub unsafe fn search(
    _haystack: *const u8,
    _haystack_len: usize,
    _window_start: usize,
    _window_end: usize,
    _result_out: *mut fre_aot_regex_runtime::FreAotRegexResultV1,
) -> u32 { 2 }
pub unsafe fn search_row(
    _row: usize,
    _haystack: *const u8,
    _haystack_len: usize,
    _window_start: usize,
    _window_end: usize,
    _result_out: *mut fre_aot_regex_runtime::FreAotRegexResultV1,
) -> u32 { 2 }
pub unsafe fn fill_spans(
    _handle: fre_aot_regex_runtime::FreAotRegexExclusiveHandleV1,
    _haystack: *const u8,
    _haystack_len: usize,
    _state: *mut fre_aot_regex_runtime::FreAotRegexIterStateV1,
    _results: *mut fre_aot_regex_runtime::FreAotRegexResultV1,
    _capacity: usize,
    _written_out: *mut usize,
) -> u32 { 2 }
pub unsafe fn regex_redux_search(
    _component: usize,
    _haystack: *const u8,
    _haystack_len: usize,
    _window_start: usize,
    _window_end: usize,
    _result_out: *mut fre_aot_regex_runtime::FreAotRegexResultV1,
) -> u32 { 2 }
pub unsafe fn capture_next(
    _haystack: *const u8,
    _haystack_len: usize,
    _state: *mut fre_aot_regex_runtime::FreAotRegexIterStateV1,
    _slots: *mut fre_aot_regex_runtime::FreAotRegexCaptureSlotV1,
    _slot_count: usize,
) -> u32 { 2 }
"#
}
