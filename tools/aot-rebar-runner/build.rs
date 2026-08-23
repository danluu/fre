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
        let artifact = fre_aot_regex::compile_native_regex_redux_aot_v1(
            target,
            fre_aot_regex::NativeRegexReduxAotLimitsV1::default(),
        )
        .expect("compile fixed public Rebar native regex-redux operation");
        let mut object_paths = Vec::with_capacity(
            fre_aot_regex::NATIVE_REGEX_REDUX_AOT_V1_COMPONENTS.saturating_add(1),
        );
        for (component, compiled) in artifact.components().iter().enumerate() {
            let component_path = output.join(format!("aot-rebar-regex-redux-{component:02}.o"));
            fs::write(&component_path, compiled.object())
                .expect("write linked regex-redux component object");
            object_paths.push(component_path);
        }
        fs::write(&object_path, artifact.reducer_object())
            .expect("write linked regex-redux whole-operation reducer object");
        object_paths.push(object_path.clone());
        fs::write(
            &generated_path,
            configured_regex_redux_source(
                &benchmark,
                &artifact,
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
        if benchmark.patterns.len() == 1 {
            let disposition =
                shared::try_compile_native_uniform_capture_reducer(&benchmark, target)
                    .expect("compile native public Rebar uniform-capture reducer");
            if let fre_aot_regex::UniformCaptureReducerCompileDisposition::Selected(selected) =
                disposition
            {
                let compiled = selected.compiled();
                let capture_receipt = selected.receipt();
                let (program_symbol, program_len) = compiled
                    .module()
                    .required_runtime_program()
                    .expect("uniform-capture reducer publishes its exact runtime program");
                fs::write(&object_path, compiled.object())
                    .expect("write linked native uniform-capture reducer object");
                fs::write(
                    &generated_path,
                    configured_source(
                        &benchmark,
                        compiled,
                        None,
                        Some(&capture_receipt),
                        None,
                        &object_path,
                        program_symbol,
                        program_len,
                        compiled.module().entry_symbol(),
                        compiled.module().prepared_span_fill_symbol(),
                        Some(selected.reducer_symbol()),
                        &architecture,
                        &operating_system,
                        feature_bits,
                        &source_commit,
                        &source_tree,
                    ),
                )
                .expect("write linked native uniform-capture reducer bindings");
                println!(
                    "cargo:rustc-link-arg-bin=fre-aot-rebar-runner={}",
                    object_path.display()
                );
                return;
            }
        }
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
                        None,
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
            shared::UniformCaptureBridgeDisposition::Prepared(bridge) => {
                let compiled = &bridge.compiled;
                let (program_symbol, program_len) = compiled
                    .module()
                    .required_runtime_program()
                    .expect("prepared uniform capture publishes its exact runtime program");
                let span_fill_symbol = compiled
                    .module()
                    .prepared_span_fill_symbol()
                    .expect("prepared uniform capture publishes SpanFill");
                fs::write(&object_path, compiled.object())
                    .expect("write linked prepared uniform-capture object");
                fs::write(
                    &generated_path,
                    configured_source(
                        &benchmark,
                        compiled,
                        Some(&bridge.receipt),
                        None,
                        None,
                        &object_path,
                        program_symbol,
                        program_len,
                        compiled.module().entry_symbol(),
                        Some(span_fill_symbol),
                        None,
                        &architecture,
                        &operating_system,
                        feature_bits,
                        &source_commit,
                        &source_tree,
                    ),
                )
                .expect("write linked prepared uniform-capture bindings");
                println!(
                    "cargo:rustc-link-arg-bin=fre-aot-rebar-runner={}",
                    object_path.display()
                );
            }
            shared::UniformCaptureBridgeDisposition::Declined { selector, .. } => {
                match shared::try_compile_participation_capture_bridge(&benchmark, target) {
                    Err(shared::ParticipationCaptureBridgeError::DfaEnvelopeExhausted(
                        exhaustion,
                    )) => {
                        let selector = selector.expect(
                            "direct participation exhausted without an authenticated ordinary selector",
                        );
                        let bridge = shared::compile_selector_capture_fallback_bridge(
                            &benchmark, selector, exhaustion,
                        )
                        .expect("compile selector-first capture fallback bridge");
                        let artifact = &bridge.rows.artifacts[0].compiled;
                        fs::write(&object_path, artifact.object())
                            .expect("write linked selector-first capture object");
                        fs::write(
                            &generated_path,
                            configured_native_row_source(
                                &benchmark,
                                &bridge.rows,
                                None,
                                Some(&bridge),
                                &architecture,
                                &operating_system,
                                feature_bits,
                                &source_commit,
                                &source_tree,
                            ),
                        )
                        .expect("write linked selector-first capture bindings");
                    }
                    Err(error) => {
                        panic!("compile exact-span participation capture bridge: {error}")
                    }
                    Ok(disposition) => match disposition {
                        shared::ParticipationCaptureBridgeDisposition::Selected(bridge) => {
                            fs::write(&object_path, bridge.artifact.object())
                                .expect("write linked participation capture object");
                            fs::write(
                                &generated_path,
                                configured_participation_capture_source(
                                    &benchmark,
                                    &bridge,
                                    &architecture,
                                    &operating_system,
                                    feature_bits,
                                    &source_commit,
                                    &source_tree,
                                ),
                            )
                            .expect("write linked participation capture bindings");
                        }
                        shared::ParticipationCaptureBridgeDisposition::Declined { .. } => {
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
                        }
                    },
                }
                println!(
                    "cargo:rustc-link-arg-bin=fre-aot-rebar-runner={}",
                    object_path.display()
                );
            }
        }
        return;
    }
    if benchmark.uses_native_row_bridge() {
        let shared = if matches!(
            benchmark.model,
            shared::Model::Count | shared::Model::SpanSum
        ) && benchmark.patterns.len() <= fre_aot_regex::ORDERED_MANY_AOT_MAX_ROWS
        {
            Some(
                shared::try_compile_shared_ordered_many_aggregate(&benchmark, target)
                    .expect("attempt shared ordered-many public Rebar aggregate"),
            )
        } else {
            None
        };
        match shared {
            Some(shared::SharedOrderedManyAggregateDisposition::Compiled(artifact)) => {
                let compiled = artifact.compiled();
                let (program_symbol, program_len) = compiled
                    .module()
                    .required_runtime_program()
                    .expect("shared ordered-many aggregate publishes its exact runtime program");
                let entry_symbol = compiled.module().entry_symbol();
                let span_fill_symbol = compiled.module().prepared_span_fill_symbol();
                let reducer_symbol = match benchmark.model {
                    shared::Model::Count => compiled
                        .module()
                        .prepared_count_symbol()
                        .expect("shared Count export"),
                    shared::Model::SpanSum => compiled
                        .module()
                        .prepared_span_sum_symbol()
                        .expect("shared SpanSum export"),
                    _ => unreachable!("shared ordered-many gate accepts only scalar models"),
                };
                fs::write(&object_path, compiled.object())
                    .expect("write linked shared ordered-many object");
                fs::write(
                    &generated_path,
                    configured_source(
                        &benchmark,
                        compiled,
                        None,
                        None,
                        Some(&artifact.receipt()),
                        &object_path,
                        program_symbol,
                        program_len,
                        entry_symbol,
                        span_fill_symbol,
                        Some(reducer_symbol),
                        &architecture,
                        &operating_system,
                        feature_bits,
                        &source_commit,
                        &source_tree,
                    ),
                )
                .expect("write linked shared ordered-many bindings");
                println!(
                    "cargo:rustc-link-arg-bin=fre-aot-rebar-runner={}",
                    object_path.display()
                );
                return;
            }
            Some(shared::SharedOrderedManyAggregateDisposition::Declined(_)) | None => {}
        }
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
            None,
            None,
            None,
            &object_path,
            program_symbol,
            program_len,
            entry_symbol,
            span_fill_symbol,
            Some(reducer_symbol),
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
    uniform_capture_receipt: Option<&fre_aot_regex::UniformCapturePreparedSpanFillCompileReceipt>,
    uniform_capture_reducer_receipt: Option<&fre_aot_regex::UniformCaptureReducerCompileReceipt>,
    ordered_many_receipt: Option<&fre_aot_regex::OrderedManyAotReceipt>,
    object_path: &std::path::Path,
    program_symbol: &str,
    program_len: usize,
    entry_symbol: &str,
    span_fill_symbol: Option<&str>,
    reducer_symbol: Option<&str>,
    architecture: &str,
    operating_system: &str,
    feature_bits: u64,
    source_commit: &str,
    source_tree: &str,
) -> String {
    let receipt = compiled.receipt();
    let prepared_uniform_capture = uniform_capture_receipt.is_some();
    let native_uniform_capture = uniform_capture_reducer_receipt.is_some();
    let uniform_capture = prepared_uniform_capture || native_uniform_capture;
    let shared_ordered_many = ordered_many_receipt.is_some();
    assert!(!(prepared_uniform_capture && native_uniform_capture));
    assert_eq!(uniform_capture, benchmark.model.is_capture());
    assert_eq!(shared_ordered_many, benchmark.patterns.len() > 1);
    assert!(!uniform_capture || !shared_ordered_many);
    if let Some(ordered) = ordered_many_receipt {
        assert_eq!(ordered.rows, benchmark.patterns.len());
        assert_eq!(
            ordered.pattern_bytes,
            benchmark.patterns.iter().map(String::len).sum::<usize>()
        );
        assert_eq!(ordered.program_sha256, receipt.program_sha256);
        assert_eq!(ordered.object_sha256, receipt.object_sha256);
        assert_eq!(ordered.exports, benchmark.model.exports());
        assert_eq!(
            Some(ordered.aggregate_strategy),
            receipt.prepared_aggregate_strategy
        );
    }
    assert_eq!(
        native_uniform_capture,
        uniform_capture && reducer_symbol.is_some()
    );
    assert!(!uniform_capture || benchmark.patterns.len() == 1);
    assert!(!prepared_uniform_capture || span_fill_symbol.is_some());
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
                shared::Model::Compile
                    | shared::Model::Count
                    | shared::Model::SpanSum
                    | shared::Model::GrepCount
                    | shared::Model::CountCaptures
                    | shared::Model::GrepCaptures
            ),
        "required Ordered-NFA capability is not legal for this operation model"
    );
    let prepare_config_version = if required_prepare_capabilities == 0 {
        2
    } else {
        3
    };
    let prepared_bulk_strategy = format!("{:?}", compiled.module().prepared_bulk_strategy());
    let native_scalar_reducer =
        shared::authenticate_native_whole_scalar_reducer(benchmark.model, compiled)
            .expect("compiled native scalar reducer failed build-time authentication");
    let span_iteration_strategy = if native_uniform_capture {
        "not-applicable".to_owned()
    } else if shared_ordered_many && benchmark.model == shared::Model::SpanSum {
        "linked-shared-ordered-many-native-span-sum-reducer-v1".to_owned()
    } else if prepared_uniform_capture {
        format!("linked-prepared-span-fill-uniform-capture-64::{prepared_bulk_strategy}")
    } else if benchmark.model != shared::Model::SpanSum {
        "not-applicable".to_owned()
    } else if native_scalar_reducer {
        "linked-native-span-sum-reducer".to_owned()
    } else if span_fill_symbol.is_some() {
        format!("linked-prepared-span-fill-64::{prepared_bulk_strategy}")
    } else {
        "linked-direct-entry-loop".to_owned()
    };
    let grep_iteration_strategy =
        if native_uniform_capture && benchmark.model == shared::Model::GrepCaptures {
            "linked-native-uniform-capture-reducer-v1".to_owned()
        } else if prepared_uniform_capture && benchmark.model == shared::Model::GrepCaptures {
            "per-line-linked-prepared-span-fill-uniform-capture-v1".to_owned()
        } else if benchmark.model == shared::Model::GrepCount {
            "linked-native-grep-count-reducer-v1".to_owned()
        } else {
            "not-applicable".to_owned()
        };
    let aggregate_strategy = if prepared_uniform_capture {
        "prepared-span-fill-static-uniform-capture-multiplier-v1".to_owned()
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
    writeln!(
        source,
        "pub const NATIVE_SCALAR_REDUCER: bool = {native_scalar_reducer};"
    )
    .unwrap();
    writeln!(
        source,
        "pub const SHARED_ORDERED_MANY_AGGREGATE: bool = {shared_ordered_many};"
    )
    .unwrap();
    writeln!(
        source,
        "pub const ORDERED_MANY_RECEIPT_SCHEMA: u32 = {};",
        ordered_many_receipt.map_or(0, |receipt| receipt.schema_version)
    )
    .unwrap();
    writeln!(
        source,
        "pub const ORDERED_MANY_SOURCES_SHA256: [u8; 32] = {:?};",
        ordered_many_receipt.map_or([0; 32], |receipt| receipt.ordered_sources_sha256)
    )
    .unwrap();
    writeln!(
        source,
        "pub const UNIFORM_CAPTURE_BRIDGE: bool = {uniform_capture};"
    )
    .unwrap();
    writeln!(
        source,
        "pub const ADAPTER: &str = {:?};",
        if shared_ordered_many {
            match benchmark.model {
                shared::Model::Count => "general-aot-shared-ordered-many-native-count-v1",
                shared::Model::SpanSum => "general-aot-shared-ordered-many-native-span-sum-v1",
                _ => unreachable!("shared ordered-many binding has a non-scalar model"),
            }
        } else if native_uniform_capture {
            match benchmark.model {
                shared::Model::CountCaptures => {
                    "general-aot-native-uniform-capture-count-reducer-v1"
                }
                shared::Model::GrepCaptures => "general-aot-native-uniform-capture-grep-reducer-v1",
                _ => unreachable!("native uniform-capture binding has a non-capture model"),
            }
        } else if prepared_uniform_capture {
            "general-aot-uniform-capture-prepared-span-fill-v1"
        } else {
            benchmark
                .model
                .adapter_for_required_capabilities(required_prepare_capabilities)
        }
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
        if uniform_capture {
            shared::Model::Count.prepare_operation_flags()
        } else {
            benchmark
                .model
                .prepare_operation_flags_for_required_capabilities(required_prepare_capabilities)
        }
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
        if shared_ordered_many {
            ""
        } else {
            benchmark.pattern()
        }
    )
    .unwrap();
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
    writeln!(source, "pub const ROW_ARTIFACT_COUNT: usize = 1;").unwrap();
    writeln!(
        source,
        "pub const ROW_TOTAL_OBJECT_BYTES: usize = {};",
        compiled.object().len()
    )
    .unwrap();
    writeln!(
        source,
        "pub const SOURCE_TO_ARTIFACT: &[usize] = &{:?};",
        vec![0_usize; benchmark.patterns.len()]
    )
    .unwrap();
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
    let uniform_proof = uniform_capture_receipt
        .map(|uniform| {
            (
                uniform.participation(),
                uniform.selector_automaton_sha256(),
                uniform.selector_program_sha256(),
                uniform.selector_object_sha256(),
            )
        })
        .or_else(|| {
            uniform_capture_reducer_receipt.map(|uniform| {
                (
                    uniform.participation(),
                    uniform.selector_automaton_sha256(),
                    uniform.selector_program_sha256(),
                    uniform.selector_object_sha256(),
                )
            })
        });
    if let Some((participation, selector_automaton, selector_program, selector_object)) =
        uniform_proof
    {
        let identity = participation.identity();
        let groups = u64::try_from(participation.participating_groups_per_match().get())
            .expect("capture multiplier fits u64");
        writeln!(
            source,
            "pub const UNIFORM_CAPTURE_ALGORITHM_VERSION: u32 = {};",
            identity.algorithm_version()
        )
        .unwrap();
        writeln!(
            source,
            "pub const UNIFORM_CAPTURE_ACCOUNTING_VERSION: u32 = {};",
            identity.accounting_version()
        )
        .unwrap();
        writeln!(
            source,
            "pub const ROW_PARTICIPATING_GROUPS: &[u64] = &[{groups}];"
        )
        .unwrap();
        writeln!(
            source,
            "pub const SOURCE_PARTICIPATING_GROUPS: &[u64] = &[{groups}];"
        )
        .unwrap();
        writeln!(
            source,
            "pub const SOURCE_MINIMUM_MATCH_BYTES: &[usize] = &[{}];",
            participation.minimum_match_bytes().get()
        )
        .unwrap();
        writeln!(
            source,
            "pub const SOURCE_CANONICAL_CAPTURE_ANNOTATIONS: &[usize] = &[{}];",
            participation.canonical_capture_annotations()
        )
        .unwrap();
        writeln!(
            source,
            "pub const SOURCE_PROOF_WORK: &[u64] = &[{}];",
            participation.work()
        )
        .unwrap();
        writeln!(
            source,
            "pub const SOURCE_PROOF_PEAK_STACK_ITEMS: &[usize] = &[{}];",
            participation.peak_stack_items()
        )
        .unwrap();
        writeln!(
            source,
            "pub const SOURCE_SELECTOR_AUTOMATON_SHA256: &[[u8; 32]] = &[{:?}];",
            selector_automaton
        )
        .unwrap();
        writeln!(
            source,
            "pub const SOURCE_SELECTOR_PROGRAM_SHA256: &[[u8; 32]] = &[{:?}];",
            selector_program
        )
        .unwrap();
        writeln!(
            source,
            "pub const SOURCE_SELECTOR_OBJECT_SHA256: &[[u8; 32]] = &[{:?}];",
            selector_object
        )
        .unwrap();
    } else {
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
    }
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
        "pub const REDUCER_SYMBOL: &str = {:?};",
        reducer_symbol.unwrap_or("")
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
    push_empty_native_regex_redux_bindings(&mut source);
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
    if let Some(reducer_symbol) = reducer_symbol {
        writeln!(source, "    #[link_name = {reducer_symbol:?}]").unwrap();
        source.push_str(
            "    fn LINKED_REDUCER(handle: fre_aot_regex_runtime::FreAotRegexExclusiveHandleV1, haystack: *const u8, haystack_len: usize, value_out: *mut u64) -> u32;\n",
        );
    }
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
    if reducer_symbol.is_some() {
        source.push_str(
            "pub unsafe fn reduce(handle: fre_aot_regex_runtime::FreAotRegexExclusiveHandleV1, haystack: *const u8, haystack_len: usize, value_out: *mut u64) -> u32 {\n    unsafe { LINKED_REDUCER(handle, haystack, haystack_len, value_out) }\n}\n",
        );
    } else {
        source.push_str(
            "pub unsafe fn reduce(_handle: fre_aot_regex_runtime::FreAotRegexExclusiveHandleV1, _haystack: *const u8, _haystack_len: usize, _value_out: *mut u64) -> u32 { fre_aot_regex_runtime::STATUS_INVALID_ARGUMENT }\n",
        );
    }
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
    push_empty_strict_capture_bindings(&mut source);
    push_empty_participation_capture_bindings(&mut source);
    push_empty_selector_capture_fallback_bindings(&mut source);
    push_empty_prepared_row_bindings(&mut source, 1);
    source
}

#[allow(
    clippy::too_many_arguments,
    reason = "the generated composite binding closes every source, target and object identity"
)]
fn configured_regex_redux_source(
    benchmark: &shared::Benchmark,
    artifact: &fre_aot_regex::NativeRegexReduxAotArtifactV1,
    architecture: &str,
    operating_system: &str,
    feature_bits: u64,
    source_commit: &str,
    source_tree: &str,
) -> String {
    assert_eq!(benchmark.model, shared::Model::RegexRedux);
    assert!(benchmark.patterns.is_empty());
    assert!(!benchmark.unicode && !benchmark.case_insensitive);
    let components = artifact.components();
    assert_eq!(components.len(), shared::REGEX_REDUX_COMPONENTS);
    assert_eq!(
        components.len(),
        fre_aot_regex::NATIVE_REGEX_REDUX_AOT_V1_COMPONENTS
    );
    assert_eq!(
        shared::REGEX_REDUX_FLATTEN_PATTERN,
        fre_aot_regex::NATIVE_REGEX_REDUX_FLATTEN_V1
    );
    assert_eq!(
        shared::REGEX_REDUX_VARIANTS,
        fre_aot_regex::NATIVE_REGEX_REDUX_VARIANTS_V1
    );
    assert!(
        shared::REGEX_REDUX_SUBSTITUTIONS
            .iter()
            .zip(fre_aot_regex::NATIVE_REGEX_REDUX_SUBSTITUTIONS_V1)
            .all(
                |((source, replacement), (native_source, native_replacement))| {
                    source == &native_source && replacement.as_bytes() == native_replacement
                }
            )
    );

    let first = components
        .first()
        .expect("regex-redux has fixed components");
    let operation_receipt = artifact.receipt();
    assert_eq!(
        operation_receipt.target,
        shared::target_from_parts(architecture, operating_system, feature_bits)
            .expect("generated regex-redux target remains supported")
    );
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
    assert_eq!(
        operation_receipt.component_entry_symbols.as_ref(),
        entry_symbols.as_slice()
    );
    assert_eq!(
        operation_receipt.component_program_sha256.as_ref(),
        program_hashes.as_slice()
    );
    assert_eq!(
        operation_receipt.component_object_sha256.as_ref(),
        object_hashes.as_slice()
    );
    assert_eq!(
        artifact.reducer_module().entry_symbol(),
        operation_receipt.reducer_symbol
    );
    assert!(
        artifact
            .reducer_module()
            .required_runtime_symbols()
            .eq(entry_symbols.iter().map(String::as_str)),
        "regex-redux reducer link closure differs from its fifteen component entries"
    );
    assert!(
        entry_symbols
            .iter()
            .all(|symbol| !symbol.starts_with("fre_aot_regex_runtime_")),
        "regex-redux reducer retains a semantic runtime helper"
    );
    assert_eq!(
        operation_receipt.abi_version,
        fre_aot_regex::NATIVE_REGEX_REDUX_AOT_V1_ABI_VERSION
    );
    assert_eq!(
        operation_receipt.request_bytes,
        fre_aot_regex::NATIVE_REGEX_REDUX_AOT_V1_REQUEST_BYTES
    );
    assert_eq!(
        operation_receipt.receipt_bytes,
        fre_aot_regex::NATIVE_REGEX_REDUX_AOT_V1_RECEIPT_BYTES
    );
    assert_eq!(
        operation_receipt.report_bytes,
        fre_aot_regex::NATIVE_REGEX_REDUX_AOT_V1_REPORT_BYTES
    );
    assert!(!artifact.reducer_object().is_empty());

    let mut source = String::new();
    source.push_str("pub const CONFIGURED: bool = true;\n");
    source.push_str("pub const NATIVE_ROW_BRIDGE: bool = false;\n");
    source.push_str("pub const NATIVE_SCALAR_REDUCER: bool = false;\n");
    source.push_str("pub const SHARED_ORDERED_MANY_AGGREGATE: bool = false;\n");
    source.push_str("pub const ORDERED_MANY_RECEIPT_SCHEMA: u32 = 0;\n");
    source.push_str("pub const ORDERED_MANY_SOURCES_SHA256: [u8; 32] = [0; 32];\n");
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
    writeln!(
        source,
        "pub const REDUCER_SYMBOL: &str = {:?};",
        operation_receipt.reducer_symbol
    )
    .unwrap();
    source.push_str("pub const ENTRY_SYMBOL: &str = \"\";\n");
    source.push_str("pub const SPAN_FILL_SYMBOL: &str = \"\";\n");
    source.push_str("pub const HAS_SPAN_FILL: bool = false;\n");
    source.push_str("pub const SPAN_ITERATION_STRATEGY: &str = \"not-applicable\";\n");
    source.push_str("pub const GREP_ITERATION_STRATEGY: &str = \"not-applicable\";\n");
    source.push_str("pub const PREPARED_BULK_STRATEGY: &str = \"None\";\n");
    source.push_str("pub const REQUIRED_RUNTIME_SYMBOLS: &str = \"\";\n");
    source.push_str("pub const ENGINE: &str = \"NativeRegexReduxAotV1\";\n");
    source.push_str(
        "pub const AGGREGATE_STRATEGY: &str = \"native-fixed-regex-redux-whole-operation-v1\";\n",
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
    writeln!(
        source,
        "pub const OBJECT_SHA256: [u8; 32] = {:?};",
        operation_receipt.reducer_object_sha256
    )
    .unwrap();
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
    writeln!(
        source,
        "pub const REGEX_REDUX_OPERATION_IDENTITY_SHA256: [u8; 32] = {:?};",
        operation_receipt.operation_identity
    )
    .unwrap();
    writeln!(
        source,
        "pub const REGEX_REDUX_REDUCER_CODE_SHA256: [u8; 32] = {:?};",
        operation_receipt.reducer_code_sha256
    )
    .unwrap();
    writeln!(
        source,
        "pub const REGEX_REDUX_REDUCER_DATA_SHA256: [u8; 32] = {:?};",
        operation_receipt.reducer_data_sha256
    )
    .unwrap();
    writeln!(
        source,
        "pub const REGEX_REDUX_REDUCER_OBJECT_SHA256: [u8; 32] = {:?};",
        operation_receipt.reducer_object_sha256
    )
    .unwrap();
    writeln!(
        source,
        "pub const REGEX_REDUX_REDUCER_RELOCATION_COUNT: usize = {};",
        operation_receipt.reducer_relocation_count
    )
    .unwrap();
    writeln!(
        source,
        "pub const REGEX_REDUX_ABI_VERSION: u32 = {};",
        operation_receipt.abi_version
    )
    .unwrap();
    writeln!(
        source,
        "pub const REGEX_REDUX_REQUEST_BYTES: usize = {};",
        operation_receipt.request_bytes
    )
    .unwrap();
    writeln!(
        source,
        "pub const REGEX_REDUX_RECEIPT_BYTES: usize = {};",
        operation_receipt.receipt_bytes
    )
    .unwrap();
    writeln!(
        source,
        "pub const REGEX_REDUX_REPORT_BYTES: usize = {};",
        operation_receipt.report_bytes
    )
    .unwrap();
    source.push_str("pub const REGEX_REDUX_SCRATCH_BUFFER_COUNT: usize = 2;\n");
    source.push_str("pub const REGEX_REDUX_SCRATCH_CAPACITY_NUMERATOR: usize = 3;\n");
    source.push_str("pub const REGEX_REDUX_SCRATCH_CAPACITY_DENOMINATOR: usize = 2;\n");
    source.push_str("pub const REGEX_REDUX_RECEIPT_SCHEMA: &str = \"u64-input-clean-variant9-substitution5-final-report-v1\";\n");
    source.push_str("pub const REGEX_REDUX_REPORT_SCHEMA: &str = \"variant9-blank-input-clean-final-lines-v1\";\n");
    writeln!(
        source,
        "pub const REGEX_REDUX_REDUCER_LINK_SYMBOLS: &[&str] = &{entry_symbols:?};"
    )
    .unwrap();
    source.push_str("pub const REGEX_REDUX_SEMANTIC_RUNTIME_SYMBOLS: &[&str] = &[];\n");
    source.push_str("pub static OBJECT_BYTES: &[u8] = include_bytes!(concat!(env!(\"OUT_DIR\"), \"/aot-rebar-artifact.o\"));\n");

    source.push_str("unsafe extern \"C\" {\n");
    writeln!(
        source,
        "    #[link_name = {:?}]",
        operation_receipt.reducer_symbol
    )
    .unwrap();
    source.push_str("    fn REGEX_REDUX_REDUCER(request: *const fre_aot_regex::NativeRegexReduxRequestV1) -> u32;\n");
    source.push_str("}\n");
    source.push_str("pub unsafe fn program_ptr() -> *const u8 { core::ptr::null() }\n");
    source.push_str("pub unsafe fn reduce(_handle: fre_aot_regex_runtime::FreAotRegexExclusiveHandleV1, _haystack: *const u8, _haystack_len: usize, _value_out: *mut u64) -> u32 { fre_aot_regex_runtime::STATUS_INVALID_ARGUMENT }\n");
    source.push_str("pub unsafe fn search(_haystack: *const u8, _haystack_len: usize, _window_start: usize, _window_end: usize, _result_out: *mut fre_aot_regex_runtime::FreAotRegexResultV1) -> u32 { fre_aot_regex_runtime::STATUS_INVALID_ARGUMENT }\n");
    source.push_str("pub unsafe fn search_row(_row: usize, _haystack: *const u8, _haystack_len: usize, _window_start: usize, _window_end: usize, _result_out: *mut fre_aot_regex_runtime::FreAotRegexResultV1) -> u32 { fre_aot_regex_runtime::STATUS_INVALID_ARGUMENT }\n");
    source.push_str("pub unsafe fn fill_spans(_handle: fre_aot_regex_runtime::FreAotRegexExclusiveHandleV1, _haystack: *const u8, _haystack_len: usize, _state: *mut fre_aot_regex_runtime::FreAotRegexIterStateV1, _results: *mut fre_aot_regex_runtime::FreAotRegexResultV1, _capacity: usize, _written_out: *mut usize) -> u32 { fre_aot_regex_runtime::STATUS_INVALID_ARGUMENT }\n");
    source.push_str("pub unsafe fn regex_redux_reduce(request: *const fre_aot_regex::NativeRegexReduxRequestV1) -> u32 { unsafe { REGEX_REDUX_REDUCER(request) } }\n");
    push_empty_strict_capture_bindings(&mut source);
    push_empty_participation_capture_bindings(&mut source);
    push_empty_selector_capture_fallback_bindings(&mut source);
    push_empty_prepared_row_bindings(&mut source, 0);
    source
}

#[allow(
    clippy::too_many_arguments,
    reason = "the generated participation binding closes the Rebar and native artifact identities"
)]
fn configured_participation_capture_source(
    benchmark: &shared::Benchmark,
    bridge: &shared::ParticipationCaptureBridge,
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
    assert!(artifact.module().required_runtime_program().is_none());
    let outer = artifact.receipt();
    let receipt = outer.native();
    let selector_symbol = artifact.selector_entry_symbol();
    let bundle_symbol = artifact.bundle_symbol();
    let participation_symbol = artifact.participation_entry_symbol();
    let strategy = match receipt.strategy {
        fre_aot_regex::NativeParticipationAotStrategyV1::DfaX86_64 => 1_u16,
        fre_aot_regex::NativeParticipationAotStrategyV1::DfaAarch64 => 2_u16,
        fre_aot_regex::NativeParticipationAotStrategyV1::NegativeEntry => {
            unreachable!("selected participation source cannot contain a negative entry")
        }
    };
    assert!(receipt.decline.is_none());
    let adapter = match benchmark.model {
        shared::Model::CountCaptures => "general-aot-native-exact-span-participation-count-v1",
        shared::Model::GrepCaptures => "general-aot-native-exact-span-participation-grep-v1",
        _ => unreachable!("participation source requires a capture model"),
    };
    let grep_strategy = if benchmark.model == shared::Model::GrepCaptures {
        "per-line-native-exact-span-participation-dfa-v1"
    } else {
        "not-applicable"
    };

    let mut source = String::new();
    source.push_str("pub const CONFIGURED: bool = true;\n");
    source.push_str("pub const NATIVE_ROW_BRIDGE: bool = true;\n");
    source.push_str("pub const NATIVE_SCALAR_REDUCER: bool = false;\n");
    source.push_str("pub const SHARED_ORDERED_MANY_AGGREGATE: bool = false;\n");
    source.push_str("pub const ORDERED_MANY_RECEIPT_SCHEMA: u32 = 0;\n");
    source.push_str("pub const ORDERED_MANY_SOURCES_SHA256: [u8; 32] = [0; 32];\n");
    source.push_str("pub const UNIFORM_CAPTURE_BRIDGE: bool = false;\n");
    source.push_str("pub const PARTICIPATION_CAPTURE_BRIDGE: bool = true;\n");
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
        "pub const ROW_ENTRY_SYMBOLS: &[&str] = &[{selector_symbol:?}];"
    )
    .unwrap();
    writeln!(
        source,
        "pub const ROW_AUTOMATON_SHA256: &[[u8; 32]] = &[{:?}];",
        receipt.selector_sha256
    )
    .unwrap();
    writeln!(
        source,
        "pub const ROW_PROGRAM_SHA256: &[[u8; 32]] = &[{:?}];",
        receipt.capture_sha256
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
        "pub const PARTICIPATION_ALGORITHM_ID: &str = {:?};",
        fre_aot_regex::NATIVE_PARTICIPATION_DFA_V1_ALGORITHM_ID
    )
    .unwrap();
    writeln!(
        source,
        "pub const PARTICIPATION_STRATEGY: u16 = {strategy};"
    )
    .unwrap();
    source.push_str("pub const PARTICIPATION_DECLINE: u16 = 0;\n");
    writeln!(
        source,
        "pub const PARTICIPATION_SEMANTIC_RUNTIME_CALLS: usize = {};",
        receipt.semantic_runtime_calls
    )
    .unwrap();
    for (name, value) in [
        ("GROUP_COUNT", receipt.groups),
        ("ASSERTIONS", receipt.assertions),
        ("ASSERTION_SIGNATURES", receipt.assertion_signatures),
        ("BYTE_CLASSES", receipt.byte_classes),
        ("DFA_STATES", receipt.dfa_states),
        ("TRANSITION_CELLS", receipt.transition_cells),
        ("BUILD_WORK", receipt.build_work),
        ("SCRATCH_BYTES", receipt.scratch_bytes),
        ("PLAN_BYTES", receipt.plan_bytes),
    ] {
        writeln!(source, "pub const PARTICIPATION_{name}: usize = {value};").unwrap();
    }
    for (name, digest) in [
        ("SOURCE", outer.source_sha256()),
        ("CAPTURE", receipt.capture_sha256),
        ("SELECTOR", receipt.selector_sha256),
        ("SELECTOR_OBJECT", receipt.selector_object_sha256),
        ("BUNDLE", receipt.bundle_sha256),
        ("EXPORT_IDENTITY", receipt.export_identity_sha256),
        ("OBJECT", receipt.object_sha256),
        ("ARTIFACT_IDENTITY", outer.artifact_identity_sha256()),
    ] {
        writeln!(
            source,
            "pub const PARTICIPATION_{name}_SHA256: [u8; 32] = {digest:?};"
        )
        .unwrap();
    }
    writeln!(
        source,
        "pub const PARTICIPATION_BUNDLE_SYMBOL: &str = {bundle_symbol:?};"
    )
    .unwrap();
    writeln!(
        source,
        "pub const PARTICIPATION_SELECTOR_SYMBOL: &str = {selector_symbol:?};"
    )
    .unwrap();
    writeln!(
        source,
        "pub const PARTICIPATION_ENTRY_SYMBOL: &str = {participation_symbol:?};"
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
    writeln!(
        source,
        "pub const ENTRY_SYMBOL: &str = {selector_symbol:?};"
    )
    .unwrap();
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
    source.push_str("pub const ENGINE: &str = \"NativeExactSpanParticipationDfaV1\";\n");
    source.push_str(
        "pub const AGGREGATE_STRATEGY: &str = \"native-exact-span-participation-dfa-v1\";\n",
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
        receipt.capture_sha256
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
    push_empty_native_regex_redux_bindings(&mut source);
    source.push_str("pub static OBJECT_BYTES: &[u8] = &[];\n");
    source.push_str("unsafe extern \"C\" {\n");
    writeln!(source, "    #[link_name = {bundle_symbol:?}]").unwrap();
    source.push_str("    static LINKED_PARTICIPATION_BUNDLE: u8;\n");
    writeln!(source, "    #[link_name = {selector_symbol:?}]").unwrap();
    source.push_str("    fn LINKED_PARTICIPATION_SELECTOR(haystack: *const u8, haystack_len: usize, window_start: usize, window_end: usize, result_out: *mut fre_aot_regex_runtime::FreAotRegexResultV1) -> u32;\n");
    writeln!(source, "    #[link_name = {participation_symbol:?}]").unwrap();
    source.push_str("    fn LINKED_PARTICIPATION_EXACT(request: *const fre_aot_regex_runtime::FreAotRegexParticipationRequestV1) -> u32;\n");
    source.push_str("}\n");
    source.push_str("pub unsafe fn program_ptr() -> *const u8 { core::ptr::null() }\n");
    source.push_str("pub unsafe fn reduce(_handle: fre_aot_regex_runtime::FreAotRegexExclusiveHandleV1, _haystack: *const u8, _haystack_len: usize, _value_out: *mut u64) -> u32 { fre_aot_regex_runtime::STATUS_INVALID_ARGUMENT }\n");
    source.push_str("pub unsafe fn search(haystack: *const u8, haystack_len: usize, window_start: usize, window_end: usize, result_out: *mut fre_aot_regex_runtime::FreAotRegexResultV1) -> u32 { unsafe { LINKED_PARTICIPATION_SELECTOR(haystack, haystack_len, window_start, window_end, result_out) } }\n");
    source.push_str("pub unsafe fn search_row(row: usize, haystack: *const u8, haystack_len: usize, window_start: usize, window_end: usize, result_out: *mut fre_aot_regex_runtime::FreAotRegexResultV1) -> u32 { if row != 0 { return fre_aot_regex_runtime::STATUS_INVALID_ARGUMENT; } unsafe { LINKED_PARTICIPATION_SELECTOR(haystack, haystack_len, window_start, window_end, result_out) } }\n");
    source.push_str("pub unsafe fn participation_bundle_ptr() -> *const u8 { &raw const LINKED_PARTICIPATION_BUNDLE }\n");
    source.push_str("pub unsafe fn participation_exact(request: *const fre_aot_regex_runtime::FreAotRegexParticipationRequestV1) -> u32 { unsafe { LINKED_PARTICIPATION_EXACT(request) } }\n");
    source.push_str("pub unsafe fn fill_spans(_handle: fre_aot_regex_runtime::FreAotRegexExclusiveHandleV1, _haystack: *const u8, _haystack_len: usize, _state: *mut fre_aot_regex_runtime::FreAotRegexIterStateV1, _results: *mut fre_aot_regex_runtime::FreAotRegexResultV1, _capacity: usize, _written_out: *mut usize) -> u32 { fre_aot_regex_runtime::STATUS_INVALID_ARGUMENT }\n");
    push_empty_strict_capture_bindings(&mut source);
    push_empty_selector_capture_fallback_bindings(&mut source);
    push_empty_prepared_row_bindings(&mut source, 1);
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
    source.push_str("pub const NATIVE_SCALAR_REDUCER: bool = false;\n");
    source.push_str("pub const SHARED_ORDERED_MANY_AGGREGATE: bool = false;\n");
    source.push_str("pub const ORDERED_MANY_RECEIPT_SCHEMA: u32 = 0;\n");
    source.push_str("pub const ORDERED_MANY_SOURCES_SHA256: [u8; 32] = [0; 32];\n");
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
    push_empty_native_regex_redux_bindings(&mut source);
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
    source.push_str("pub unsafe fn capture_next(haystack: *const u8, haystack_len: usize, state: *mut fre_aot_regex_runtime::FreAotRegexIterStateV1, slots: *mut fre_aot_regex_runtime::FreAotRegexCaptureSlotV1, slot_count: usize) -> u32 { unsafe { LINKED_STRICT_CAPTURE_NEXT(haystack, haystack_len, state, slots, slot_count) } }\n");
    push_empty_participation_capture_bindings(&mut source);
    push_empty_selector_capture_fallback_bindings(&mut source);
    push_empty_prepared_row_bindings(&mut source, 1);
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
    selector_capture_fallback: Option<&shared::SelectorCaptureFallbackBridge>,
    architecture: &str,
    operating_system: &str,
    feature_bits: u64,
    source_commit: &str,
    source_tree: &str,
) -> String {
    assert!(
        benchmark.uses_native_row_bridge()
            || benchmark.uses_uniform_capture_bridge()
            || selector_capture_fallback.is_some()
    );
    assert!(!bridge.artifacts.is_empty());
    assert_eq!(bridge.source_to_artifact.len(), benchmark.patterns.len());
    assert!(!(uniform_capture_receipts.is_some() && selector_capture_fallback.is_some()));
    assert_eq!(
        uniform_capture_receipts.is_some() || selector_capture_fallback.is_some(),
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
        match artifact.route {
            shared::NativeRowRoute::Ordinary => {
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
            shared::NativeRowRoute::PreparedOrderedNfaV15 => {
                assert_eq!(
                    compiled.receipt().required_prepare_capabilities,
                    fre_aot_regex::PREPARED_CAPABILITY_ORDERED_NFA_V15
                );
                assert_eq!(
                    compiled.module().required_prepare_capabilities(),
                    fre_aot_regex::PREPARED_CAPABILITY_ORDERED_NFA_V15
                );
                assert_eq!(
                    compiled.module().prepared_bulk_strategy(),
                    Some(fre_aot_regex::PreparedBulkStrategy::NativeOrderedNfaLoop)
                );
                assert!(compiled.module().prepared_entry_symbol().is_some());
                assert!(compiled.module().prepared_span_fill_symbol().is_some());
                assert!(compiled.module().required_runtime_program().is_some());
            }
        }
    }

    let has_prepared_v15 = bridge
        .artifacts
        .iter()
        .any(|artifact| artifact.route.is_prepared());
    let (prepare_max_handle_bytes, prepare_max_scratch_bytes, prepare_max_setup_work) =
        if has_prepared_v15 {
            (
                fre_aot_regex::DEFAULT_FROZEN_ORDERED_NFA_V1_MAX_HANDLE_BYTES as u64,
                fre_aot_regex::FROZEN_ORDERED_NFA_V1_MAX_SCRATCH_BYTES as u64,
                fre_aot_regex::FROZEN_ORDERED_NFA_V1_MAX_SETUP_WORK,
            )
        } else {
            (0, 0, 0)
        };
    assert!(!uniform_capture_receipts.is_some_and(|_| has_prepared_v15));
    let uniform_capture = uniform_capture_receipts.is_some();
    let selector_fallback = selector_capture_fallback.is_some();
    assert!(!selector_fallback || !has_prepared_v15);
    let adapter = if selector_fallback {
        assert_eq!(benchmark.model, shared::Model::GrepCaptures);
        "general-aot-native-selector-negative-certificate-stock-positive-capture-fallback-v1"
    } else {
        match (benchmark.model, has_prepared_v15) {
            (shared::Model::Count, false) => "general-aot-native-row-bridge-count-v1",
            (shared::Model::Count, true) => {
                "general-aot-native-row-bridge-count-mixed-prepared-ordered-nfa-v15-v1"
            }
            (shared::Model::SpanSum, false) => "general-aot-native-row-bridge-count-spans-v1",
            (shared::Model::SpanSum, true) => {
                "general-aot-native-row-bridge-count-spans-mixed-prepared-ordered-nfa-v15-v1"
            }
            (shared::Model::GrepCount, false) => "general-aot-native-row-bridge-grep-v1",
            (shared::Model::GrepCount, true) => {
                "general-aot-native-row-bridge-grep-mixed-prepared-ordered-nfa-v15-v1"
            }
            (shared::Model::CountCaptures, false) => {
                "general-aot-uniform-capture-native-row-count-adapter-loop-v1"
            }
            (shared::Model::GrepCaptures, false) => {
                "general-aot-uniform-capture-native-row-grep-adapter-loop-v1"
            }
            (shared::Model::CountCaptures | shared::Model::GrepCaptures, true) => {
                unreachable!("capture rows never select a prepared fallback")
            }
            (shared::Model::Compile | shared::Model::RegexRedux, _) => {
                unreachable!("parser excludes this multi-pattern model")
            }
        }
    };
    let row_strategy = if has_prepared_v15 {
        "native-independent-span-row-selector-mixed-prepared-v15-v1"
    } else {
        "native-independent-span-row-selector-v1"
    };
    let grep_row_strategy = if has_prepared_v15 {
        "per-line-native-independent-span-row-exists-mixed-prepared-v15-v1"
    } else {
        "per-line-native-independent-span-row-exists-v1"
    };
    let aggregate_strategy = if selector_fallback {
        "native-selector-negative-certificate-with-stock-positive-capture-fallback-v1"
    } else if uniform_capture {
        "native-row-static-uniform-capture-multiplier-v1"
    } else if benchmark.model == shared::Model::GrepCount {
        grep_row_strategy
    } else {
        row_strategy
    };
    let span_iteration_strategy = if benchmark.model == shared::Model::SpanSum {
        aggregate_strategy
    } else {
        "not-applicable"
    };
    let grep_iteration_strategy = if selector_fallback {
        "per-line-native-selector-negative-certificate-stock-positive-capture-fallback-v1"
    } else {
        match benchmark.model {
            shared::Model::GrepCount => grep_row_strategy,
            shared::Model::GrepCaptures => "per-line-native-row-static-uniform-capture-v1",
            _ => "not-applicable",
        }
    };
    let first_source_ordinals = bridge
        .artifacts
        .iter()
        .map(|artifact| artifact.first_source_ordinal)
        .collect::<Vec<_>>();
    let entry_symbols = bridge
        .artifacts
        .iter()
        .map(shared::NativeRowArtifact::entry_symbol)
        .collect::<Vec<_>>();
    let row_required_prepare_capabilities = bridge
        .artifacts
        .iter()
        .map(|artifact| artifact.compiled.module().required_prepare_capabilities())
        .collect::<Vec<_>>();
    let row_prepare_config_versions = bridge
        .artifacts
        .iter()
        .map(|artifact| {
            if artifact.route.is_prepared() {
                3_u32
            } else {
                0_u32
            }
        })
        .collect::<Vec<_>>();
    let row_prepare_operation_flags = bridge
        .artifacts
        .iter()
        .map(|artifact| {
            if artifact.route.is_prepared() {
                shared::Model::Count.prepare_operation_flags()
            } else {
                0
            }
        })
        .collect::<Vec<_>>();
    let row_program_symbols = bridge
        .artifacts
        .iter()
        .map(|artifact| {
            artifact
                .compiled
                .module()
                .required_runtime_program()
                .map_or("", |(symbol, _)| symbol)
        })
        .collect::<Vec<_>>();
    let row_program_lens = bridge
        .artifacts
        .iter()
        .map(|artifact| {
            artifact
                .compiled
                .module()
                .required_runtime_program()
                .map_or(0, |(_, len)| len)
        })
        .collect::<Vec<_>>();
    let row_span_fill_symbols = bridge
        .artifacts
        .iter()
        .map(|artifact| {
            artifact
                .compiled
                .module()
                .prepared_span_fill_symbol()
                .unwrap_or("")
        })
        .collect::<Vec<_>>();
    let row_prepared_bulk_strategies = bridge
        .artifacts
        .iter()
        .map(|artifact| format!("{:?}", artifact.compiled.module().prepared_bulk_strategy()))
        .collect::<Vec<_>>();
    let row_required_runtime_symbols = bridge
        .artifacts
        .iter()
        .map(|artifact| {
            artifact
                .compiled
                .module()
                .required_runtime_symbols()
                .collect::<Vec<_>>()
                .join(",")
        })
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
    writeln!(source, "pub const NATIVE_SCALAR_REDUCER: bool = false;").unwrap();
    writeln!(
        source,
        "pub const SHARED_ORDERED_MANY_AGGREGATE: bool = false;"
    )
    .unwrap();
    writeln!(source, "pub const ORDERED_MANY_RECEIPT_SCHEMA: u32 = 0;").unwrap();
    writeln!(
        source,
        "pub const ORDERED_MANY_SOURCES_SHA256: [u8; 32] = [0; 32];"
    )
    .unwrap();
    writeln!(
        source,
        "pub const UNIFORM_CAPTURE_BRIDGE: bool = {uniform_capture};"
    )
    .unwrap();
    if let Some(fallback) = selector_capture_fallback {
        let resource = match fallback.direct_participation.resource {
            fre_aot_regex::NativeParticipationAotResourceV1::DfaStates => "DfaStates",
            fre_aot_regex::NativeParticipationAotResourceV1::BuildWork => "BuildWork",
            _ => unreachable!("selector fallback admits only the fixed DFA envelope"),
        };
        source.push_str("pub const SELECTOR_CAPTURE_FALLBACK_BRIDGE: bool = true;\n");
        writeln!(
            source,
            "pub const SELECTOR_CAPTURE_POSITIVE_FALLBACK_SYMBOL: &str = {:?};",
            shared::REBAR_SELECTOR_CAPTURE_POSITIVE_FALLBACK_SYMBOL,
        )
        .unwrap();
        source.push_str(
            "pub const SELECTOR_CAPTURE_POSITIVE_FALLBACK_PROFILE: &str = \"rust-regex-1.12.4-captures\";\n",
        );
        writeln!(
            source,
            "pub const SELECTOR_CAPTURE_DIRECT_RESOURCE: &str = {resource:?};"
        )
        .unwrap();
        writeln!(
            source,
            "pub const SELECTOR_CAPTURE_DIRECT_REQUIRED: usize = {};",
            fallback.direct_participation.required,
        )
        .unwrap();
        writeln!(
            source,
            "pub const SELECTOR_CAPTURE_DIRECT_LIMIT: usize = {};",
            fallback.direct_participation.limit,
        )
        .unwrap();
    } else {
        push_empty_selector_capture_fallback_bindings(&mut source);
    }
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
    writeln!(
        source,
        "pub const ROW_PREPARE_MAX_HANDLE_BYTES: u64 = {prepare_max_handle_bytes};"
    )
    .unwrap();
    writeln!(
        source,
        "pub const ROW_PREPARE_MAX_SCRATCH_BYTES: u64 = {prepare_max_scratch_bytes};"
    )
    .unwrap();
    writeln!(
        source,
        "pub const ROW_PREPARE_MAX_SETUP_WORK: u64 = {prepare_max_setup_work};"
    )
    .unwrap();
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
        "pub const ROW_REQUIRED_PREPARE_CAPABILITIES: &[u64] = &{row_required_prepare_capabilities:?};"
    )
    .unwrap();
    writeln!(
        source,
        "pub const ROW_PREPARE_CONFIG_VERSIONS: &[u32] = &{row_prepare_config_versions:?};"
    )
    .unwrap();
    writeln!(
        source,
        "pub const ROW_PREPARE_OPERATION_FLAGS: &[u64] = &{row_prepare_operation_flags:?};"
    )
    .unwrap();
    writeln!(
        source,
        "pub const ROW_PROGRAM_SYMBOLS: &[&str] = &{row_program_symbols:?};"
    )
    .unwrap();
    writeln!(
        source,
        "pub const ROW_PROGRAM_LENS: &[usize] = &{row_program_lens:?};"
    )
    .unwrap();
    writeln!(
        source,
        "pub const ROW_SPAN_FILL_SYMBOLS: &[&str] = &{row_span_fill_symbols:?};"
    )
    .unwrap();
    writeln!(
        source,
        "pub const ROW_PREPARED_BULK_STRATEGIES: &[&str] = &{row_prepared_bulk_strategies:?};"
    )
    .unwrap();
    writeln!(
        source,
        "pub const ROW_REQUIRED_RUNTIME_SYMBOLS: &[&str] = &{row_required_runtime_symbols:?};"
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
    push_empty_native_regex_redux_bindings(&mut source);
    writeln!(source, "pub static OBJECT_BYTES: &[u8] = &[];").unwrap();
    source.push_str("unsafe extern \"C\" {\n");
    for (index, artifact) in bridge.artifacts.iter().enumerate() {
        let entry_symbol = artifact.entry_symbol();
        writeln!(source, "    #[link_name = {entry_symbol:?}]").unwrap();
        match artifact.route {
            shared::NativeRowRoute::Ordinary => {
                writeln!(source, "    fn LINKED_ROW_ENTRY_{index}(haystack: *const u8, haystack_len: usize, window_start: usize, window_end: usize, result_out: *mut fre_aot_regex_runtime::FreAotRegexResultV1) -> u32;").unwrap();
            }
            shared::NativeRowRoute::PreparedOrderedNfaV15 => {
                writeln!(source, "    fn LINKED_ROW_ENTRY_{index}(handle: fre_aot_regex_runtime::FreAotRegexExclusiveHandleV1, haystack: *const u8, haystack_len: usize, window_start: usize, window_end: usize, result_out: *mut fre_aot_regex_runtime::FreAotRegexResultV1) -> u32;").unwrap();
                let (program_symbol, _) = artifact
                    .compiled
                    .module()
                    .required_runtime_program()
                    .expect("authenticated prepared row program");
                writeln!(source, "    #[link_name = {program_symbol:?}]").unwrap();
                writeln!(source, "    static LINKED_ROW_PROGRAM_{index}: u8;").unwrap();
            }
        }
    }
    source.push_str("}\n");
    if has_prepared_v15 {
        source.push_str("pub unsafe fn search_row(row: usize, haystack: *const u8, haystack_len: usize, window_start: usize, window_end: usize, result_out: *mut fre_aot_regex_runtime::FreAotRegexResultV1) -> u32 {\n    match row {\n");
        for (index, artifact) in bridge.artifacts.iter().enumerate() {
            if artifact.route == shared::NativeRowRoute::Ordinary {
                writeln!(source, "        {index} => unsafe {{ LINKED_ROW_ENTRY_{index}(haystack, haystack_len, window_start, window_end, result_out) }},").unwrap();
            }
        }
        source.push_str("        _ => fre_aot_regex_runtime::STATUS_INVALID_ARGUMENT,\n    }\n}\n");
    } else {
        source.push_str(
            "pub type LinkedRowSearch = unsafe extern \"C\" fn(*const u8, usize, usize, usize, *mut fre_aot_regex_runtime::FreAotRegexResultV1) -> u32;\n",
        );
        source.push_str("pub static LINKED_ROW_SEARCHES: &[LinkedRowSearch] = &[\n");
        for index in 0..entry_symbols.len() {
            writeln!(source, "    LINKED_ROW_ENTRY_{index},").unwrap();
        }
        source.push_str("];\n");
        source.push_str(
            "pub unsafe fn search_row(row: usize, haystack: *const u8, haystack_len: usize, window_start: usize, window_end: usize, result_out: *mut fre_aot_regex_runtime::FreAotRegexResultV1) -> u32 {\n    let Some(search) = LINKED_ROW_SEARCHES.get(row) else { return fre_aot_regex_runtime::STATUS_INVALID_ARGUMENT; };\n    unsafe { search(haystack, haystack_len, window_start, window_end, result_out) }\n}\n",
        );
    }
    source.push_str("pub unsafe fn row_program_ptr(row: usize) -> *const u8 {\n    match row {\n");
    for (index, artifact) in bridge.artifacts.iter().enumerate() {
        if artifact.route.is_prepared() {
            writeln!(
                source,
                "        {index} => &raw const LINKED_ROW_PROGRAM_{index},"
            )
            .unwrap();
        }
    }
    source.push_str("        _ => core::ptr::null(),\n    }\n}\n");
    source.push_str("pub unsafe fn search_row_prepared(row: usize, handle: fre_aot_regex_runtime::FreAotRegexExclusiveHandleV1, haystack: *const u8, haystack_len: usize, window_start: usize, window_end: usize, result_out: *mut fre_aot_regex_runtime::FreAotRegexResultV1) -> u32 {\n    match row {\n");
    for (index, artifact) in bridge.artifacts.iter().enumerate() {
        if artifact.route.is_prepared() {
            writeln!(source, "        {index} => unsafe {{ LINKED_ROW_ENTRY_{index}(handle, haystack, haystack_len, window_start, window_end, result_out) }},").unwrap();
        }
    }
    source.push_str("        _ => fre_aot_regex_runtime::STATUS_INVALID_ARGUMENT,\n    }\n}\n");
    source.push_str("pub unsafe fn program_ptr() -> *const u8 { core::ptr::null() }\n");
    source.push_str(
        "pub unsafe fn reduce(_handle: fre_aot_regex_runtime::FreAotRegexExclusiveHandleV1, _haystack: *const u8, _haystack_len: usize, _value_out: *mut u64) -> u32 { fre_aot_regex_runtime::STATUS_INVALID_ARGUMENT }\n",
    );
    source.push_str(
        "pub unsafe fn search(_haystack: *const u8, _haystack_len: usize, _window_start: usize, _window_end: usize, _result_out: *mut fre_aot_regex_runtime::FreAotRegexResultV1) -> u32 { fre_aot_regex_runtime::STATUS_INVALID_ARGUMENT }\n",
    );
    source.push_str(
        "pub unsafe fn fill_spans(_handle: fre_aot_regex_runtime::FreAotRegexExclusiveHandleV1, _haystack: *const u8, _haystack_len: usize, _state: *mut fre_aot_regex_runtime::FreAotRegexIterStateV1, _results: *mut fre_aot_regex_runtime::FreAotRegexResultV1, _capacity: usize, _written_out: *mut usize) -> u32 { fre_aot_regex_runtime::STATUS_INVALID_ARGUMENT }\n",
    );
    push_empty_strict_capture_bindings(&mut source);
    push_empty_participation_capture_bindings(&mut source);
    source
}

fn push_empty_native_regex_redux_bindings(source: &mut String) {
    source.push_str("pub const REGEX_REDUX_OPERATION_IDENTITY_SHA256: [u8; 32] = [0; 32];\n");
    source.push_str("pub const REGEX_REDUX_REDUCER_CODE_SHA256: [u8; 32] = [0; 32];\n");
    source.push_str("pub const REGEX_REDUX_REDUCER_DATA_SHA256: [u8; 32] = [0; 32];\n");
    source.push_str("pub const REGEX_REDUX_REDUCER_OBJECT_SHA256: [u8; 32] = [0; 32];\n");
    source.push_str("pub const REGEX_REDUX_REDUCER_RELOCATION_COUNT: usize = 0;\n");
    source.push_str("pub const REGEX_REDUX_ABI_VERSION: u32 = 0;\n");
    source.push_str("pub const REGEX_REDUX_REQUEST_BYTES: usize = 0;\n");
    source.push_str("pub const REGEX_REDUX_RECEIPT_BYTES: usize = 0;\n");
    source.push_str("pub const REGEX_REDUX_REPORT_BYTES: usize = 0;\n");
    source.push_str("pub const REGEX_REDUX_SCRATCH_BUFFER_COUNT: usize = 0;\n");
    source.push_str("pub const REGEX_REDUX_SCRATCH_CAPACITY_NUMERATOR: usize = 0;\n");
    source.push_str("pub const REGEX_REDUX_SCRATCH_CAPACITY_DENOMINATOR: usize = 0;\n");
    source.push_str("pub const REGEX_REDUX_RECEIPT_SCHEMA: &str = \"\";\n");
    source.push_str("pub const REGEX_REDUX_REPORT_SCHEMA: &str = \"\";\n");
    source.push_str("pub const REGEX_REDUX_REDUCER_LINK_SYMBOLS: &[&str] = &[];\n");
    source.push_str("pub const REGEX_REDUX_SEMANTIC_RUNTIME_SYMBOLS: &[&str] = &[];\n");
    source.push_str("pub unsafe fn regex_redux_reduce(_request: *const fre_aot_regex::NativeRegexReduxRequestV1) -> u32 { fre_aot_regex::NATIVE_REGEX_REDUX_AOT_V1_STATUS_INVALID_ARGUMENT }\n");
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

fn push_empty_participation_capture_bindings(source: &mut String) {
    source.push_str("pub const PARTICIPATION_CAPTURE_BRIDGE: bool = false;\n");
    source.push_str("pub const PARTICIPATION_ALGORITHM_ID: &str = \"\";\n");
    source.push_str("pub const PARTICIPATION_STRATEGY: u16 = 0;\n");
    source.push_str("pub const PARTICIPATION_DECLINE: u16 = 0;\n");
    source.push_str("pub const PARTICIPATION_SEMANTIC_RUNTIME_CALLS: usize = 0;\n");
    source.push_str("pub const PARTICIPATION_GROUP_COUNT: usize = 0;\n");
    source.push_str("pub const PARTICIPATION_ASSERTIONS: usize = 0;\n");
    source.push_str("pub const PARTICIPATION_ASSERTION_SIGNATURES: usize = 0;\n");
    source.push_str("pub const PARTICIPATION_BYTE_CLASSES: usize = 0;\n");
    source.push_str("pub const PARTICIPATION_DFA_STATES: usize = 0;\n");
    source.push_str("pub const PARTICIPATION_TRANSITION_CELLS: usize = 0;\n");
    source.push_str("pub const PARTICIPATION_BUILD_WORK: usize = 0;\n");
    source.push_str("pub const PARTICIPATION_SCRATCH_BYTES: usize = 0;\n");
    source.push_str("pub const PARTICIPATION_PLAN_BYTES: usize = 0;\n");
    source.push_str("pub const PARTICIPATION_SOURCE_SHA256: [u8; 32] = [0; 32];\n");
    source.push_str("pub const PARTICIPATION_CAPTURE_SHA256: [u8; 32] = [0; 32];\n");
    source.push_str("pub const PARTICIPATION_SELECTOR_SHA256: [u8; 32] = [0; 32];\n");
    source.push_str("pub const PARTICIPATION_SELECTOR_OBJECT_SHA256: [u8; 32] = [0; 32];\n");
    source.push_str("pub const PARTICIPATION_BUNDLE_SHA256: [u8; 32] = [0; 32];\n");
    source.push_str("pub const PARTICIPATION_EXPORT_IDENTITY_SHA256: [u8; 32] = [0; 32];\n");
    source.push_str("pub const PARTICIPATION_OBJECT_SHA256: [u8; 32] = [0; 32];\n");
    source.push_str("pub const PARTICIPATION_ARTIFACT_IDENTITY_SHA256: [u8; 32] = [0; 32];\n");
    source.push_str("pub const PARTICIPATION_BUNDLE_SYMBOL: &str = \"\";\n");
    source.push_str("pub const PARTICIPATION_SELECTOR_SYMBOL: &str = \"\";\n");
    source.push_str("pub const PARTICIPATION_ENTRY_SYMBOL: &str = \"\";\n");
    source
        .push_str("pub unsafe fn participation_bundle_ptr() -> *const u8 { core::ptr::null() }\n");
    source.push_str("pub unsafe fn participation_exact(_request: *const fre_aot_regex_runtime::FreAotRegexParticipationRequestV1) -> u32 { fre_aot_regex_runtime::STATUS_INVALID_ARGUMENT }\n");
}

fn push_empty_selector_capture_fallback_bindings(source: &mut String) {
    source.push_str("pub const SELECTOR_CAPTURE_FALLBACK_BRIDGE: bool = false;\n");
    source.push_str("pub const SELECTOR_CAPTURE_POSITIVE_FALLBACK_SYMBOL: &str = \"\";\n");
    source.push_str("pub const SELECTOR_CAPTURE_POSITIVE_FALLBACK_PROFILE: &str = \"\";\n");
    source.push_str("pub const SELECTOR_CAPTURE_DIRECT_RESOURCE: &str = \"\";\n");
    source.push_str("pub const SELECTOR_CAPTURE_DIRECT_REQUIRED: usize = 0;\n");
    source.push_str("pub const SELECTOR_CAPTURE_DIRECT_LIMIT: usize = 0;\n");
}

fn push_empty_prepared_row_bindings(source: &mut String, row_count: usize) {
    let zeros_u64 = vec![0_u64; row_count];
    let zeros_u32 = vec![0_u32; row_count];
    let zeros_usize = vec![0_usize; row_count];
    let empty_strings = vec![""; row_count];
    let none_strategies = vec!["None"; row_count];
    writeln!(
        source,
        "pub const ROW_REQUIRED_PREPARE_CAPABILITIES: &[u64] = &{zeros_u64:?};"
    )
    .unwrap();
    writeln!(
        source,
        "pub const ROW_PREPARE_CONFIG_VERSIONS: &[u32] = &{zeros_u32:?};"
    )
    .unwrap();
    writeln!(
        source,
        "pub const ROW_PREPARE_OPERATION_FLAGS: &[u64] = &{zeros_u64:?};"
    )
    .unwrap();
    writeln!(
        source,
        "pub const ROW_PROGRAM_SYMBOLS: &[&str] = &{empty_strings:?};"
    )
    .unwrap();
    writeln!(
        source,
        "pub const ROW_PROGRAM_LENS: &[usize] = &{zeros_usize:?};"
    )
    .unwrap();
    writeln!(
        source,
        "pub const ROW_SPAN_FILL_SYMBOLS: &[&str] = &{empty_strings:?};"
    )
    .unwrap();
    writeln!(
        source,
        "pub const ROW_PREPARED_BULK_STRATEGIES: &[&str] = &{none_strategies:?};"
    )
    .unwrap();
    writeln!(
        source,
        "pub const ROW_REQUIRED_RUNTIME_SYMBOLS: &[&str] = &{empty_strings:?};"
    )
    .unwrap();
    source.push_str("pub const ROW_PREPARE_MAX_HANDLE_BYTES: u64 = 0;\n");
    source.push_str("pub const ROW_PREPARE_MAX_SCRATCH_BYTES: u64 = 0;\n");
    source.push_str("pub const ROW_PREPARE_MAX_SETUP_WORK: u64 = 0;\n");
    source.push_str(
        "pub unsafe fn row_program_ptr(_row: usize) -> *const u8 { core::ptr::null() }\n",
    );
    source.push_str(
        "pub unsafe fn search_row_prepared(_row: usize, _handle: fre_aot_regex_runtime::FreAotRegexExclusiveHandleV1, _haystack: *const u8, _haystack_len: usize, _window_start: usize, _window_end: usize, _result_out: *mut fre_aot_regex_runtime::FreAotRegexResultV1) -> u32 { fre_aot_regex_runtime::STATUS_INVALID_ARGUMENT }\n",
    );
}

fn stub_source() -> &'static str {
    r#"pub const CONFIGURED: bool = false;
pub const NATIVE_ROW_BRIDGE: bool = false;
pub const NATIVE_SCALAR_REDUCER: bool = false;
pub const SHARED_ORDERED_MANY_AGGREGATE: bool = false;
pub const ORDERED_MANY_RECEIPT_SCHEMA: u32 = 0;
pub const ORDERED_MANY_SOURCES_SHA256: [u8; 32] = [0; 32];
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
pub const PARTICIPATION_CAPTURE_BRIDGE: bool = false;
pub const PARTICIPATION_ALGORITHM_ID: &str = "";
pub const PARTICIPATION_STRATEGY: u16 = 0;
pub const PARTICIPATION_DECLINE: u16 = 0;
pub const PARTICIPATION_SEMANTIC_RUNTIME_CALLS: usize = 0;
pub const PARTICIPATION_GROUP_COUNT: usize = 0;
pub const PARTICIPATION_ASSERTIONS: usize = 0;
pub const PARTICIPATION_ASSERTION_SIGNATURES: usize = 0;
pub const PARTICIPATION_BYTE_CLASSES: usize = 0;
pub const PARTICIPATION_DFA_STATES: usize = 0;
pub const PARTICIPATION_TRANSITION_CELLS: usize = 0;
pub const PARTICIPATION_BUILD_WORK: usize = 0;
pub const PARTICIPATION_SCRATCH_BYTES: usize = 0;
pub const PARTICIPATION_PLAN_BYTES: usize = 0;
pub const PARTICIPATION_SOURCE_SHA256: [u8; 32] = [0; 32];
pub const PARTICIPATION_CAPTURE_SHA256: [u8; 32] = [0; 32];
pub const PARTICIPATION_SELECTOR_SHA256: [u8; 32] = [0; 32];
pub const PARTICIPATION_SELECTOR_OBJECT_SHA256: [u8; 32] = [0; 32];
pub const PARTICIPATION_BUNDLE_SHA256: [u8; 32] = [0; 32];
pub const PARTICIPATION_EXPORT_IDENTITY_SHA256: [u8; 32] = [0; 32];
pub const PARTICIPATION_OBJECT_SHA256: [u8; 32] = [0; 32];
pub const PARTICIPATION_ARTIFACT_IDENTITY_SHA256: [u8; 32] = [0; 32];
pub const PARTICIPATION_BUNDLE_SYMBOL: &str = "";
pub const PARTICIPATION_SELECTOR_SYMBOL: &str = "";
pub const PARTICIPATION_ENTRY_SYMBOL: &str = "";
pub const SELECTOR_CAPTURE_FALLBACK_BRIDGE: bool = false;
pub const SELECTOR_CAPTURE_POSITIVE_FALLBACK_SYMBOL: &str = "";
pub const SELECTOR_CAPTURE_POSITIVE_FALLBACK_PROFILE: &str = "";
pub const SELECTOR_CAPTURE_DIRECT_RESOURCE: &str = "";
pub const SELECTOR_CAPTURE_DIRECT_REQUIRED: usize = 0;
pub const SELECTOR_CAPTURE_DIRECT_LIMIT: usize = 0;
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
pub const ROW_REQUIRED_PREPARE_CAPABILITIES: &[u64] = &[];
pub const ROW_PREPARE_CONFIG_VERSIONS: &[u32] = &[];
pub const ROW_PREPARE_OPERATION_FLAGS: &[u64] = &[];
pub const ROW_PROGRAM_SYMBOLS: &[&str] = &[];
pub const ROW_PROGRAM_LENS: &[usize] = &[];
pub const ROW_SPAN_FILL_SYMBOLS: &[&str] = &[];
pub const ROW_PREPARED_BULK_STRATEGIES: &[&str] = &[];
pub const ROW_REQUIRED_RUNTIME_SYMBOLS: &[&str] = &[];
pub const ROW_PREPARE_MAX_HANDLE_BYTES: u64 = 0;
pub const ROW_PREPARE_MAX_SCRATCH_BYTES: u64 = 0;
pub const ROW_PREPARE_MAX_SETUP_WORK: u64 = 0;
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
pub const REGEX_REDUX_OPERATION_IDENTITY_SHA256: [u8; 32] = [0; 32];
pub const REGEX_REDUX_REDUCER_CODE_SHA256: [u8; 32] = [0; 32];
pub const REGEX_REDUX_REDUCER_DATA_SHA256: [u8; 32] = [0; 32];
pub const REGEX_REDUX_REDUCER_OBJECT_SHA256: [u8; 32] = [0; 32];
pub const REGEX_REDUX_REDUCER_RELOCATION_COUNT: usize = 0;
pub const REGEX_REDUX_ABI_VERSION: u32 = 0;
pub const REGEX_REDUX_REQUEST_BYTES: usize = 0;
pub const REGEX_REDUX_RECEIPT_BYTES: usize = 0;
pub const REGEX_REDUX_REPORT_BYTES: usize = 0;
pub const REGEX_REDUX_SCRATCH_BUFFER_COUNT: usize = 0;
pub const REGEX_REDUX_SCRATCH_CAPACITY_NUMERATOR: usize = 0;
pub const REGEX_REDUX_SCRATCH_CAPACITY_DENOMINATOR: usize = 0;
pub const REGEX_REDUX_RECEIPT_SCHEMA: &str = "";
pub const REGEX_REDUX_REPORT_SCHEMA: &str = "";
pub const REGEX_REDUX_REDUCER_LINK_SYMBOLS: &[&str] = &[];
pub const REGEX_REDUX_SEMANTIC_RUNTIME_SYMBOLS: &[&str] = &[];
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
pub unsafe fn row_program_ptr(_row: usize) -> *const u8 { core::ptr::null() }
pub unsafe fn search_row_prepared(
    _row: usize,
    _handle: fre_aot_regex_runtime::FreAotRegexExclusiveHandleV1,
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
pub unsafe fn regex_redux_reduce(
    _request: *const fre_aot_regex::NativeRegexReduxRequestV1,
) -> u32 { fre_aot_regex::NATIVE_REGEX_REDUX_AOT_V1_STATUS_INVALID_ARGUMENT }
pub unsafe fn capture_next(
    _haystack: *const u8,
    _haystack_len: usize,
    _state: *mut fre_aot_regex_runtime::FreAotRegexIterStateV1,
    _slots: *mut fre_aot_regex_runtime::FreAotRegexCaptureSlotV1,
    _slot_count: usize,
) -> u32 { 2 }
pub unsafe fn participation_bundle_ptr() -> *const u8 { core::ptr::null() }
pub unsafe fn participation_exact(
    _request: *const fre_aot_regex_runtime::FreAotRegexParticipationRequestV1,
) -> u32 { 2 }
"#
}
