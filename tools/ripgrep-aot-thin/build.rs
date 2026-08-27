use std::env;
use std::fmt::Write as _;
use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;

use fre_aot_regex::{
    Architecture, CompileMode, CompileRequest, EngineKind, EngineSelectionReason,
    IndependentExistsBatchCompileError, OperatingSystem, OutputContract, PreparedBulkStrategy,
    PreparedAggregateExports, PreparedAggregateStrategy, StartAccelerator, Target, compile,
    compile_with_exact_finite_selected_end_grep_count,
    compile_with_independent_exists_batch,
    compile_with_independent_matching_lf_line_witness,
};
use fre_syntax::RustProfile;

mod build_proof;
mod build_support;
mod build_target;
mod exact64_set_build;
mod first_candidate_build;
mod first_candidate_receipt;
mod lf_line_witness_build;
mod lf_line_witness_receipt;
mod registry_key;

use build_proof::{
    exact_crlf_free_finite_language, exact_nonempty_lf_free_finite_language_proof,
    exact_nonempty_lf_free_singleton_literal, ripgrep_grep_count_profile,
};
use build_support::{
    BuildMode, BuildOutput, EXACT64_SETS_FILE_ENV, PATTERNS_FILE_ENV, VARIANTS_ENV, VariantPolicy,
    exact64_sets_path, patterns_path, purge_generated_artifacts, read_exact64_sets, read_patterns,
};
use build_target::{CARGO_TARGET_FEATURE_ENV, FEATURES_ENV, selected_features};
use exact64_set_build::generate as generate_exact64_sets;
use first_candidate_build::FirstCandidateRegistryBuild;
use lf_line_witness_build::MatchingLfLineWitnessRegistryBuild;
use registry_key::manifest_profile_key;

const ENABLE_MATCHING_LF_LINE_WITNESS: bool = true;

#[allow(
    clippy::too_many_lines,
    reason = "artifact compilation and generated registry construction form one build transaction"
)]
fn main() {
    println!("cargo:rerun-if-changed=build_proof.rs");
    println!("cargo:rerun-if-changed=build_support.rs");
    println!("cargo:rerun-if-changed=build_target.rs");
    println!("cargo:rerun-if-changed=exact64_set_build.rs");
    println!("cargo:rerun-if-changed=first_candidate_build.rs");
    println!("cargo:rerun-if-changed=first_candidate_receipt.rs");
    println!("cargo:rerun-if-changed=lf_line_witness_build.rs");
    println!("cargo:rerun-if-changed=lf_line_witness_receipt.rs");
    println!("cargo:rerun-if-changed=registry_key.rs");
    println!("cargo:rerun-if-env-changed={FEATURES_ENV}");
    println!("cargo:rerun-if-env-changed={CARGO_TARGET_FEATURE_ENV}");
    println!("cargo:rerun-if-env-changed=FRE_RIPGREP_AOT_PATTERN_FILTER");
    println!("cargo:rerun-if-env-changed={PATTERNS_FILE_ENV}");
    println!("cargo:rerun-if-env-changed={VARIANTS_ENV}");
    println!("cargo:rerun-if-env-changed={EXACT64_SETS_FILE_ENV}");
    let manifest_dir = PathBuf::from(
        env::var_os("CARGO_MANIFEST_DIR").expect("Cargo supplies CARGO_MANIFEST_DIR"),
    );
    let patterns_path = patterns_path(&manifest_dir, env::var_os(PATTERNS_FILE_ENV).as_deref())
        .unwrap_or_else(|error| panic!("AOT patterns path: {error}"));
    println!("cargo:rerun-if-changed={}", patterns_path.display());
    let exact64_sets_path = exact64_sets_path(
        &manifest_dir,
        env::var_os(EXACT64_SETS_FILE_ENV).as_deref(),
    )
    .unwrap_or_else(|error| panic!("AOT exact64 sets path: {error}"));
    if let Some(path) = &exact64_sets_path {
        println!("cargo:rerun-if-changed={}", path.display());
    }
    let variant_policy = VariantPolicy::parse(env::var_os(VARIANTS_ENV).as_deref())
        .unwrap_or_else(|error| panic!("AOT variant policy: {error}"));
    let out_dir = PathBuf::from(env::var_os("OUT_DIR").expect("Cargo supplies OUT_DIR"));
    purge_generated_artifacts(&out_dir)
        .unwrap_or_else(|error| panic!("purge stale AOT build artifacts: {error}"));
    let target = target().unwrap_or_else(|error| panic!("AOT target: {error}"));
    let exact64_sets = exact64_sets_path
        .as_deref()
        .map(read_exact64_sets)
        .transpose()
        .unwrap_or_else(|error| panic!("AOT exact64 set manifest: {error}"))
        .unwrap_or_default();
    let public_exact64_fixture = manifest_dir.join("testdata/public-exact64-sets.tsv");
    let public_exact64_fixture_selected = exact64_sets_path.as_deref().is_some_and(|path| {
        matches!(
            (fs::canonicalize(path), fs::canonicalize(&public_exact64_fixture)),
            (Ok(selected), Ok(public)) if selected == public
        )
    });
    let public_first_candidate_fixture = manifest_dir.join("testdata/public-first-candidate.tsv");
    let public_first_candidate_fixture_selected = matches!(
        (
            fs::canonicalize(&patterns_path),
            fs::canonicalize(&public_first_candidate_fixture),
        ),
        (Ok(selected), Ok(public)) if selected == public
    );
    let mut patterns = read_patterns(&patterns_path)
        .unwrap_or_else(|error| panic!("AOT patterns manifest: {error}"));
    let manifest_pattern_count = patterns.len();
    let mut manifest_profile_key_rows = String::new();
    for pattern in &patterns {
        let key = manifest_profile_key(&pattern.source, pattern.case_insensitive);
        writeln!(&mut manifest_profile_key_rows, "    {key:?},")
            .expect("String writes cannot fail");
    }
    if let Some(filter) = env::var_os("FRE_RIPGREP_AOT_PATTERN_FILTER") {
        let ids = filter.to_string_lossy();
        let ids = ids.split(',').collect::<Vec<_>>();
        patterns.retain(|pattern| ids.contains(&pattern.id.as_str()));
        assert!(
            !patterns.is_empty(),
            "FRE_RIPGREP_AOT_PATTERN_FILTER selected no patterns"
        );
    }
    let mut generated = format!(
        "#[allow(unused_imports, reason = \"a fully declined aggregate-only registry declares no handle-taking symbol\")]\nuse fre_aot_regex_runtime::FreAotRegexExclusiveHandleV1;\n\n#[allow(unused_imports, reason = \"additive ABI types are absent unless their explicit build profile is selected\")]\nuse super::{{AbiHaystack, AbiResult, AotMode, AotOutput, BackendFactory, CompiledSpec, GrepCountSpec, NativeFillOutcome, NativeIterState, PreparedSpanFillFactory, fill_native_spans}};\n\npub(super) const BUILD_VARIANT_POLICY: &str = {:?};\n#[allow(dead_code, reason = \"generated-registry cardinality is checked by the package tests\")]\npub(super) const BUILD_PATTERN_COUNT: usize = {};\n#[allow(dead_code, reason = \"the raw-free manifest-key cardinality is checked by the package tests\")]\npub(super) const BUILD_MANIFEST_PATTERN_COUNT: usize = {manifest_pattern_count};\n\n/// Raw-free identities for every pattern/profile row in the selected manifest.\npub(super) const ALL_MANIFEST_PROFILE_KEYS: &[[u8; 32]] = &[\n{manifest_profile_key_rows}];\n\n#[allow(unsafe_code, clippy::unreadable_literal, reason = \"generated declarations for audited FRE AOT object entries\")]\nunsafe extern \"C\" {{\n",
        variant_policy.name(),
        patterns.len(),
    );
    let mut native_fills = String::new();
    let mut rows = String::new();
    let mut grep_count_rows = String::new();
    let mut grep_count_admitted = 0_usize;
    let mut first_candidates = FirstCandidateRegistryBuild::new();
    let mut matching_lf_line_witnesses = MatchingLfLineWitnessRegistryBuild::new();
    let mut objects = Vec::new();

    for pattern in &patterns {
        for (mode, mode_name, mode_source, build_mode) in [
            (CompileMode::Fast, "fast", "AotMode::Fast", BuildMode::Fast),
            (
                CompileMode::Optimizing,
                "optimizing",
                "AotMode::Optimizing",
                BuildMode::Optimizing,
            ),
        ] {
            for (output, output_name, output_source, build_output) in [
                (
                    OutputContract::Exists,
                    "exists",
                    "AotOutput::Exists",
                    BuildOutput::Exists,
                ),
                (
                    OutputContract::Span,
                    "span",
                    "AotOutput::Span",
                    BuildOutput::Span,
                ),
            ] {
                if !variant_policy.includes(build_mode, build_output) {
                    continue;
                }
                let mut profile = RustProfile::default();
                profile.options.case_insensitive = pattern.case_insensitive;
                let independent_first_candidate_literal = (mode == CompileMode::Optimizing
                    && output == OutputContract::Exists)
                    .then(|| exact_nonempty_lf_free_singleton_literal(&pattern.source, &profile))
                    .flatten();
                let independent_lf_line_witness_proof = (mode == CompileMode::Optimizing
                    && output == OutputContract::Exists)
                    .then(|| {
                        exact_nonempty_lf_free_finite_language_proof(&pattern.source, &profile)
                    })
                    .flatten();
                let request = CompileRequest::new(pattern.source.clone(), target)
                    .profile(profile)
                    .mode(mode)
                    .output(output);
                let compiled = if output == OutputContract::Exists {
                    if ENABLE_MATCHING_LF_LINE_WITNESS
                        && independent_lf_line_witness_proof.is_some()
                    {
                        compile_with_independent_matching_lf_line_witness(request)
                    } else {
                        compile_with_independent_exists_batch(request)
                    }
                } else {
                    compile(request).map_err(IndependentExistsBatchCompileError::from)
                }
                .unwrap_or_else(|error| {
                    panic!(
                        "compile {} {mode_name}/{output_name} {:?}: {error}",
                        pattern.id, pattern.source
                    )
                });
                let receipt = compiled.receipt();
                if mode == CompileMode::Optimizing && output == OutputContract::Exists {
                    first_candidates.consider(
                        pattern,
                        target,
                        &compiled,
                        independent_first_candidate_literal.as_deref(),
                    );
                    matching_lf_line_witnesses.consider(
                        pattern,
                        target,
                        &compiled,
                        independent_lf_line_witness_proof,
                    );
                }
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
                        if compiled.module().direct_exists_batch_symbol().is_some() =>
                    {
                        "direct-exists-batch-v1"
                    }
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
                    Some(PreparedBulkStrategy::NativeOrderedNfaLoop) => "native-ordered-nfa-loop",
                    None if compiled.module().direct_exists_batch_symbol().is_some() => {
                        "native-direct-trusted-full-window-loop"
                    }
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
                    let exists_batch = if output == OutputContract::Exists {
                        if let Some(symbol) = compiled.module().direct_exists_batch_symbol() {
                            let batch = format!("exists_batch_{stem}");
                            writeln!(
                                &mut generated,
                                "    #[link_name = {symbol:?}] fn {batch}(haystacks: *const AbiHaystack, count: usize, matched: *mut u8, processed: *mut usize) -> u32;",
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
                        "BackendFactory::Native {{ search: {declaration}, fill: {fill}, exists_batch: {exists_batch} }}"
                    )
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

    if variant_policy.includes(BuildMode::Optimizing, BuildOutput::GrepCount) {
        for pattern in &patterns {
            let profile = ripgrep_grep_count_profile(pattern.case_insensitive);
            if !exact_crlf_free_finite_language(&pattern.source, &profile) {
                continue;
            }
            let compiled = compile_with_exact_finite_selected_end_grep_count(
                CompileRequest::new(pattern.source.clone(), target)
                    .profile(profile)
                    .mode(CompileMode::Optimizing)
                    .output(OutputContract::SelectedEnd),
            )
            .unwrap_or_else(|error| {
                panic!(
                    "compile {} optimizing/grep-count after independent proof: {error}",
                    pattern.id
                )
            });
            let module = compiled.module();
            let receipt = compiled.receipt();
            let report = module
                .exact_finite_selected_end_grep_count_aot_report()
                .copied();
            let entry_symbol = module.prepared_grep_count_symbol();
            if report.is_none() && entry_symbol.is_none() {
                assert!(
                    module.prepared_aggregate_exports() == PreparedAggregateExports::NONE
                        && module.prepared_aggregate_strategy().is_none()
                        && receipt.prepared_aggregate_exports == PreparedAggregateExports::NONE
                        && receipt.prepared_aggregate_strategy.is_none(),
                    "structurally declined GrepCount artifact {} retained partial aggregate state",
                    pattern.id
                );
                continue;
            }
            let (Some(report), Some(entry_symbol)) = (report, entry_symbol) else {
                panic!(
                    "GrepCount artifact {} disagrees between compiler report and exported entry",
                    pattern.id
                );
            };
            let Some((program_symbol, program_len)) = module.required_runtime_program() else {
                panic!(
                    "authenticated GrepCount artifact {} has no preparation program",
                    pattern.id
                );
            };
            let artifact_identity = compiled.program().artifact_identity();
            assert!(
                report.artifact_identity == artifact_identity
                    && receipt.program_sha256 == artifact_identity
                    && report.output == OutputContract::SelectedEnd
                    && receipt.output == OutputContract::SelectedEnd
                    && receipt.mode == CompileMode::Optimizing
                    && receipt.target == target
                    && receipt.line_terminator == b'\n'
                    && report.source_count != 0
                    && report.source_bytes != 0
                    && report.maximum_width != 0
                    && report.module_sha256 != [0; 32]
                    && report.ordinary_entry_sha256 != [0; 32]
                    && report.reducer_code_sha256 != [0; 32]
                    && program_len != 0
                    && module.prepared_aggregate_exports() == PreparedAggregateExports::GREP_COUNT
                    && receipt.prepared_aggregate_exports == PreparedAggregateExports::GREP_COUNT
                    && module.prepared_aggregate_strategy()
                        == Some(PreparedAggregateStrategy::NativeFused)
                    && receipt.prepared_aggregate_strategy
                        == Some(PreparedAggregateStrategy::NativeFused)
                    && module.prepared_count_symbol().is_none()
                    && module.prepared_span_sum_symbol().is_none()
                    && module.required_runtime_symbols().next().is_none()
                    && !receipt.runtime_helper_required
                    && receipt.required_prepare_capabilities == 0
                    && receipt.object_bytes == compiled.object().len(),
                "GrepCount artifact {} failed compiler report/identity/export authentication",
                pattern.id
            );

            let stem = format!("{}_optimizing_grep_count", pattern.id);
            let object = out_dir.join(format!("{stem}.o"));
            fs::write(&object, compiled.object()).unwrap_or_else(|error| {
                panic!("write generated object {}: {error}", object.display())
            });
            objects.push(object);
            let entry_declaration = format!("grep_count_entry_{stem}");
            let program_declaration = format!("grep_count_program_{stem}");
            writeln!(
                &mut generated,
                "    #[link_name = {entry_symbol:?}] fn {entry_declaration}(handle: FreAotRegexExclusiveHandleV1, haystack: *const u8, haystack_len: usize, value_out: *mut u64) -> u32;",
            )
            .expect("String writes cannot fail");
            writeln!(
                &mut generated,
                "    #[link_name = {program_symbol:?}] static {program_declaration}: [u8; {program_len}];",
            )
            .expect("String writes cannot fail");
            let description = format!(
                "mode=optimizing,route=compiled-prepared,api=grep-count-v1,aggregate=native-fused,proof=exact-finite-nonempty-nonnullable-assertion-free-crlf-free,engine={},reason={},accelerator={},target={}-{},features={:#x},states={},dfa_states={}",
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
            writeln!(
                &mut grep_count_rows,
                "    GrepCountSpec {{ mode: AotMode::Optimizing, pattern: {:?}, case_insensitive: {}, description: {:?}, entry: {entry_declaration}, program: unsafe {{ &{program_declaration} }} }},",
                pattern.source,
                pattern.case_insensitive,
                description,
            )
            .expect("String writes cannot fail");
            grep_count_admitted += 1;
        }
    }
    generated.push_str("}\n\n");
    generated.push_str(&native_fills);
    generated.push_str(
        "\n#[allow(unsafe_code, reason = \"generated registry borrows exact immutable program symbols from linked compiler objects\")]\npub(super) const SPECS: &[CompiledSpec] = &[\n",
    );
    generated.push_str(&rows);
    generated.push_str("];\n");
    writeln!(
        &mut generated,
        "\n#[allow(dead_code, reason = \"generated GrepCount admission cardinality is checked by the package tests\")]\npub(super) const BUILD_GREP_COUNT_ADMITTED_COUNT: usize = {grep_count_admitted};"
    )
    .expect("String writes cannot fail");
    generated.push_str(
        "\n#[allow(unsafe_code, reason = \"generated registry borrows exact immutable GrepCount program symbols from linked compiler objects\")]\npub(super) const GREP_COUNT_SPECS: &[GrepCountSpec] = &[\n",
    );
    generated.push_str(&grep_count_rows);
    generated.push_str("];\n");
    fs::write(out_dir.join("registry.rs"), generated).expect("write generated registry");
    fs::write(
        out_dir.join("first_candidate_registry.rs"),
        first_candidates.finish(target, public_first_candidate_fixture_selected),
    )
    .expect("write generated exact-singleton first-candidate registry");
    fs::write(
        out_dir.join("lf_line_witness_registry.rs"),
        matching_lf_line_witnesses.finish(
            target,
            ENABLE_MATCHING_LF_LINE_WITNESS && public_first_candidate_fixture_selected,
        ),
    )
    .expect("write generated matching-LF-line witness registry");
    let exact64_generated = generate_exact64_sets(
        &exact64_sets,
        target,
        &out_dir,
        exact64_sets_path.is_some(),
        public_exact64_fixture_selected,
    );
    fs::write(
        out_dir.join("exact64_set_registry.rs"),
        exact64_generated.source,
    )
    .expect("write generated exact64 set registry");
    objects.extend(exact64_generated.objects);
    if !objects.is_empty() {
        make_archive(&out_dir, &objects);
    }
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
    let explicit_features = env::var_os(FEATURES_ENV);
    let cargo_features = env::var_os(CARGO_TARGET_FEATURE_ENV);
    let features = selected_features(
        base.architecture,
        explicit_features.as_deref(),
        cargo_features.as_deref(),
    )?;
    base.with_features(features)
        .map_err(|error| error.to_string())
}

fn make_archive(out_dir: &Path, objects: &[PathBuf]) {
    let archive = out_dir.join("libfre_ripgrep_aot_objects.a");
    match fs::remove_file(&archive) {
        Ok(()) => {}
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
        Err(error) => panic!("remove stale AOT object archive {}: {error}", archive.display()),
    }
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
