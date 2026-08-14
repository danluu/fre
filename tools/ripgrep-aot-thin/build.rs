use std::env;
use std::fmt::Write as _;
use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;

use fre_aot_regex::{
    Architecture, CompileMode, CompileRequest, CpuFeature, EngineKind, EngineSelectionReason,
    FeatureSet, OperatingSystem, OutputContract, PreparedBulkStrategy, StartAccelerator, Target,
    compile,
};
use fre_syntax::RustProfile;

#[derive(Debug)]
struct Pattern {
    id: String,
    case_insensitive: bool,
    source: String,
}

#[allow(
    clippy::too_many_lines,
    reason = "artifact compilation and generated registry construction form one build transaction"
)]
fn main() {
    println!("cargo:rerun-if-changed=patterns.tsv");
    println!("cargo:rerun-if-env-changed=FRE_RIPGREP_AOT_FEATURES");
    println!("cargo:rerun-if-env-changed=FRE_RIPGREP_AOT_PATTERN_FILTER");
    let out_dir = PathBuf::from(env::var_os("OUT_DIR").expect("Cargo supplies OUT_DIR"));
    let target = target().unwrap_or_else(|error| panic!("AOT target: {error}"));
    let mut patterns = read_patterns(Path::new("patterns.tsv"));
    if let Some(filter) = env::var_os("FRE_RIPGREP_AOT_PATTERN_FILTER") {
        let ids = filter.to_string_lossy();
        let ids = ids.split(',').collect::<Vec<_>>();
        patterns.retain(|pattern| ids.contains(&pattern.id.as_str()));
        assert!(
            !patterns.is_empty(),
            "FRE_RIPGREP_AOT_PATTERN_FILTER selected no patterns"
        );
    }
    let mut generated = String::from(
        "use fre_aot_regex_runtime::FreAotRegexExclusiveHandleV1;\n\n#[allow(unused_imports, reason = \"additive fill ABI types are absent when every selected artifact takes a compatibility route\")]\nuse super::{AbiHaystack, AbiResult, AotMode, AotOutput, BackendFactory, CompiledSpec, NativeFillOutcome, NativeIterState, PreparedSpanFillFactory, fill_native_spans};\n\n#[allow(unsafe_code, clippy::unreadable_literal, reason = \"generated declarations for audited FRE AOT object entries\")]\nunsafe extern \"C\" {\n",
    );
    let mut native_fills = String::new();
    let mut rows = String::new();
    let mut objects = Vec::new();

    for pattern in &patterns {
        for (mode, mode_name, mode_source) in [
            (CompileMode::Fast, "fast", "AotMode::Fast"),
            (CompileMode::Optimizing, "optimizing", "AotMode::Optimizing"),
        ] {
            for (output, output_name, output_source) in [
                (OutputContract::Exists, "exists", "AotOutput::Exists"),
                (OutputContract::Span, "span", "AotOutput::Span"),
            ] {
                let mut profile = RustProfile::default();
                profile.options.case_insensitive = pattern.case_insensitive;
                let compiled = compile(
                    CompileRequest::new(pattern.source.clone(), target)
                        .profile(profile)
                        .mode(mode)
                        .output(output),
                )
                .unwrap_or_else(|error| {
                    panic!(
                        "compile {} {mode_name}/{output_name} {:?}: {error}",
                        pattern.id, pattern.source
                    )
                });
                let receipt = compiled.receipt();
                let has_prepared_entry = compiled.module().prepared_entry_symbol().is_some();
                let route = if has_prepared_entry {
                    "compiled-prepared"
                } else if compiled.module().required_runtime_symbol().is_none() {
                    "direct-native"
                } else {
                    "portable-runtime"
                };
                let batch_api = match output {
                    OutputContract::Exists
                        if compiled.module().prepared_exists_batch_symbol().is_some() =>
                    {
                        "exists-batch-v1"
                    }
                    OutputContract::Span
                        if compiled.module().prepared_span_fill_symbol().is_some() =>
                    {
                        "span-fill-v1"
                    }
                    OutputContract::Exists => "per-haystack",
                    OutputContract::SelectedEnd => "per-result",
                    OutputContract::Span => "rust-span-fill",
                };
                let bulk = match compiled.module().prepared_bulk_strategy() {
                    Some(PreparedBulkStrategy::RuntimeHelper) => "runtime-helper",
                    Some(PreparedBulkStrategy::NativePreparedLoop) => "native-prepared-loop",
                    Some(PreparedBulkStrategy::NativeTrustedPreflightLoop) => {
                        "native-trusted-preflight-loop"
                    }
                    Some(PreparedBulkStrategy::NativeTrustedPreflightRuntimeBulk) => {
                        "native-trusted-preflight-runtime-bulk"
                    }
                    Some(PreparedBulkStrategy::NativeFrozenLoop) => "native-frozen-loop",
                    None if has_prepared_entry => "compatibility",
                    None => "none",
                };
                let description = format!(
                    "mode={mode_name},route={route},api={batch_api},bulk={bulk},engine={},reason={},accelerator={},target={}-{},features={:#x},states={},dfa_states={}",
                    engine_name(receipt.engine),
                    reason_name(receipt.engine_selection_reason),
                    accelerator_name(receipt.start_accelerator),
                    architecture_name(target.architecture),
                    os_name(target.operating_system),
                    target.features.bits(),
                    receipt.thompson_states,
                    receipt
                        .dfa
                        .map_or_else(|| "-".to_owned(), |stats| stats.forward_states.to_string()),
                );
                let stem = format!("{}_{}_{}", pattern.id, mode_name, output_name);
                let backend = if let Some(prepared_entry_symbol) =
                    compiled.module().prepared_entry_symbol()
                {
                    let object = out_dir.join(format!("{stem}.o"));
                    fs::write(&object, compiled.object()).unwrap_or_else(|error| {
                        panic!("write generated object {}: {error}", object.display())
                    });
                    objects.push(object);
                    let declaration = format!("prepared_entry_{stem}");
                    writeln!(
                        &mut generated,
                        "    #[link_name = {prepared_entry_symbol:?}] fn {declaration}(handle: FreAotRegexExclusiveHandleV1, haystack: *const u8, haystack_len: usize, window_start: usize, window_end: usize, result: *mut AbiResult) -> u32;",
                    )
                    .expect("String writes cannot fail");
                    let (runtime_program_symbol, runtime_program_len) = compiled
                        .module()
                        .required_runtime_program()
                        .unwrap_or_else(|| {
                            panic!(
                                "compiled prepared entry {prepared_entry_symbol:?} for {stem} has no required runtime program"
                            )
                        });
                    let program_declaration = format!("program_{stem}");
                    writeln!(
                        &mut generated,
                        "    #[link_name = {runtime_program_symbol:?}] static {program_declaration}: [u8; {runtime_program_len}];",
                    )
                    .expect("String writes cannot fail");
                    let span_fill = if output == OutputContract::Span {
                        if let Some(symbol) = compiled.module().prepared_span_fill_symbol() {
                            let fill = format!("span_fill_prepared_{stem}");
                            writeln!(
                                &mut generated,
                                "    #[link_name = {symbol:?}] fn {fill}(handle: FreAotRegexExclusiveHandleV1, haystack: *const u8, haystack_len: usize, state: *mut NativeIterState, results: *mut AbiResult, capacity: usize, written: *mut usize) -> u32;",
                            )
                            .expect("String writes cannot fail");
                            format!("Some(PreparedSpanFillFactory::Compiled({fill}))")
                        } else {
                            let fill = format!("span_fill_compat_prepared_{stem}");
                            writeln!(
                                &mut native_fills,
                                "#[allow(unsafe_code, reason = \"compatibility shim calls its exact compiler-produced prepared AOT entry\")]\nfn {fill}(handle: FreAotRegexExclusiveHandleV1, haystack: &[u8], state: &mut NativeIterState, output: &mut [core::mem::MaybeUninit<AbiResult>]) -> NativeFillOutcome {{\n    // SAFETY: this closure invokes the exact compiler-produced prepared Span entry with its exclusively owned handle; status 1 initializes result and no borrowed argument is retained.\n    unsafe {{\n        fill_native_spans(haystack, state, output, |haystack, start, result| {{\n            {declaration}(handle, haystack.as_ptr(), haystack.len(), start, haystack.len(), result)\n        }})\n    }}\n}}\n"
                            )
                            .expect("String writes cannot fail");
                            format!("Some(PreparedSpanFillFactory::Compatibility({fill}))")
                        }
                    } else {
                        "None".to_owned()
                    };
                    let exists_batch = if output == OutputContract::Exists {
                        if let Some(symbol) = compiled.module().prepared_exists_batch_symbol() {
                            let batch = format!("exists_batch_prepared_{stem}");
                            writeln!(
                                &mut generated,
                                "    #[link_name = {symbol:?}] fn {batch}(handle: FreAotRegexExclusiveHandleV1, haystacks: *const AbiHaystack, count: usize, matched: *mut u8, processed: *mut usize) -> u32;",
                            )
                            .expect("String writes cannot fail");
                            format!("Some({batch})")
                        } else {
                            "None".to_owned()
                        }
                    } else {
                        "None".to_owned()
                    };
                    format!(
                        "BackendFactory::Prepared {{ search: {declaration}, program: unsafe {{ &{program_declaration} }}, span_fill: {span_fill}, exists_batch: {exists_batch} }}"
                    )
                } else if route == "direct-native" {
                    let object = out_dir.join(format!("{stem}.o"));
                    fs::write(&object, compiled.object()).unwrap_or_else(|error| {
                        panic!("write generated object {}: {error}", object.display())
                    });
                    objects.push(object);
                    let declaration = format!("entry_{stem}");
                    writeln!(
                        &mut generated,
                        "    #[link_name = {:?}] fn {declaration}(haystack: *const u8, haystack_len: usize, window_start: usize, window_end: usize, result: *mut AbiResult) -> u32;",
                        compiled.module().entry_symbol(),
                    )
                    .expect("String writes cannot fail");
                    let fill = if output == OutputContract::Span {
                        let fill = format!("fill_{stem}");
                        writeln!(
                            &mut native_fills,
                            "#[allow(unsafe_code, reason = \"generated shim calls its exact compiler-produced AOT entry\")]\nfn {fill}(haystack: &[u8], state: &mut NativeIterState, output: &mut [core::mem::MaybeUninit<AbiResult>]) -> NativeFillOutcome {{\n    // SAFETY: this closure invokes the exact compiler-produced Span entry; status 1 initializes result and no argument is retained.\n    unsafe {{\n        fill_native_spans(haystack, state, output, |haystack, start, result| {{\n            {declaration}(haystack.as_ptr(), haystack.len(), start, haystack.len(), result)\n        }})\n    }}\n}}\n"
                        )
                        .expect("String writes cannot fail");
                        format!("Some({fill})")
                    } else {
                        "None".to_owned()
                    };
                    format!("BackendFactory::Native {{ search: {declaration}, fill: {fill} }}")
                } else {
                    let program = out_dir.join(format!("{stem}.program"));
                    let bytes = compiled
                        .program()
                        .serialize()
                        .unwrap_or_else(|error| panic!("serialize {stem}: {error}"));
                    fs::write(&program, bytes).unwrap_or_else(|error| {
                        panic!("write generated program {}: {error}", program.display())
                    });
                    format!(
                        "BackendFactory::Runtime(include_bytes!(concat!(env!(\"OUT_DIR\"), \"/{stem}.program\")))"
                    )
                };
                writeln!(
                    &mut rows,
                    "    CompiledSpec {{ mode: {mode_source}, output: {output_source}, pattern: {:?}, case_insensitive: {}, description: {:?}, backend: {backend} }},",
                    pattern.source,
                    pattern.case_insensitive,
                    description,
                )
                .expect("String writes cannot fail");
            }
        }
    }
    generated.push_str("}\n\n");
    generated.push_str(&native_fills);
    generated.push_str(
        "\n#[allow(unsafe_code, reason = \"generated registry borrows exact immutable program symbols from linked compiler objects\")]\npub(super) const SPECS: &[CompiledSpec] = &[\n",
    );
    generated.push_str(&rows);
    generated.push_str("];\n");
    fs::write(out_dir.join("registry.rs"), generated).expect("write generated registry");
    if !objects.is_empty() {
        make_archive(&out_dir, &objects);
    }
}

fn read_patterns(path: &Path) -> Vec<Pattern> {
    let text = fs::read_to_string(path).expect("read patterns.tsv");
    let patterns = text
        .lines()
        .filter(|line| !line.is_empty() && !line.starts_with('#'))
        .map(|line| {
            let mut columns = line.splitn(3, '\t');
            let id = columns.next().expect("pattern id").to_owned();
            assert!(
                id.bytes()
                    .all(|byte| byte.is_ascii_alphanumeric() || byte == b'_'),
                "pattern id must be a Rust identifier suffix: {id:?}"
            );
            let case_insensitive = match columns.next() {
                Some("0") => false,
                Some("1") => true,
                other => panic!("invalid case-insensitive field for {id}: {other:?}"),
            };
            let source = columns
                .next()
                .unwrap_or_else(|| panic!("missing pattern for {id}"))
                .to_owned();
            Pattern {
                id,
                case_insensitive,
                source,
            }
        })
        .collect::<Vec<_>>();
    assert!(!patterns.is_empty(), "patterns.tsv must not be empty");
    patterns
}

fn target() -> Result<Target, String> {
    let architecture = env::var("CARGO_CFG_TARGET_ARCH").map_err(|error| error.to_string())?;
    let os = env::var("CARGO_CFG_TARGET_OS").map_err(|error| error.to_string())?;
    let base = match (architecture.as_str(), os.as_str()) {
        ("x86_64", "linux") => Target::x86_64_linux(),
        ("x86_64", "macos") => Target::x86_64_macos(),
        ("aarch64", "linux") => Target::aarch64_linux(),
        ("aarch64", "macos") => Target::aarch64_macos(),
        _ => return Err(format!("unsupported Cargo target {architecture}-{os}")),
    };
    let mut features = FeatureSet::EMPTY;
    if let Some(value) = env::var_os("FRE_RIPGREP_AOT_FEATURES") {
        for name in value
            .to_string_lossy()
            .split(',')
            .filter(|name| !name.is_empty())
        {
            let feature = match name {
                "sse2" => CpuFeature::X86Sse2,
                "avx2" => CpuFeature::X86Avx2,
                "avx512f" => CpuFeature::X86Avx512F,
                "avx512bw" => CpuFeature::X86Avx512Bw,
                "avx512vl" => CpuFeature::X86Avx512Vl,
                "asimd" => CpuFeature::Aarch64Asimd,
                "sve" => CpuFeature::Aarch64Sve,
                "sve2" => CpuFeature::Aarch64Sve2,
                _ => return Err(format!("unknown FRE_RIPGREP_AOT_FEATURES value {name:?}")),
            };
            features = features.with(feature);
        }
    }
    base.with_features(features)
        .map_err(|error| error.to_string())
}

fn make_archive(out_dir: &Path, objects: &[PathBuf]) {
    let archive = out_dir.join("libfre_ripgrep_aot_objects.a");
    let archiver = env::var_os("AR").unwrap_or_else(|| "ar".into());
    let output = Command::new(&archiver)
        .arg("crs")
        .arg(&archive)
        .args(objects)
        .output()
        .unwrap_or_else(|error| panic!("run {}: {error}", archiver.to_string_lossy()));
    assert!(
        output.status.success(),
        "archive AOT objects failed: {}{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    println!("cargo:rustc-link-search=native={}", out_dir.display());
    println!("cargo:rustc-link-lib=static=fre_ripgrep_aot_objects");
}

const fn architecture_name(value: Architecture) -> &'static str {
    match value {
        Architecture::X86_64 => "x86_64",
        Architecture::Aarch64 => "aarch64",
    }
}

const fn os_name(value: OperatingSystem) -> &'static str {
    match value {
        OperatingSystem::Linux => "linux",
        OperatingSystem::Macos => "macos",
    }
}

const fn engine_name(value: EngineKind) -> &'static str {
    match value {
        EngineKind::OrderedNfa => "ordered-nfa",
        EngineKind::OrderedDfa => "ordered-dfa",
        EngineKind::OrderedContextDfa => "ordered-context-dfa",
    }
}

const fn reason_name(value: EngineSelectionReason) -> &'static str {
    match value {
        EngineSelectionReason::FastMode => "fast-mode",
        EngineSelectionReason::CompleteDfa => "complete-dfa",
        EngineSelectionReason::CompleteContextDfa => "complete-context-dfa",
        EngineSelectionReason::ContextAssertions => "context-assertions",
        EngineSelectionReason::DeterminizationResourceLimit => "resource-limit",
    }
}

const fn accelerator_name(value: StartAccelerator) -> &'static str {
    match value {
        StartAccelerator::None => "none",
        StartAccelerator::Scalar => "scalar",
        StartAccelerator::X86Sse2 => "x86-sse2",
        StartAccelerator::X86Avx2 => "x86-avx2",
        StartAccelerator::X86Avx512Bw => "x86-avx512bw",
        StartAccelerator::Aarch64Asimd => "aarch64-asimd",
        StartAccelerator::Aarch64Sve => "aarch64-sve",
        StartAccelerator::Aarch64Sve2 => "aarch64-sve2",
    }
}
