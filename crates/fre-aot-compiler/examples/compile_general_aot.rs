use std::{env, fs, process::ExitCode};

use fre_aot_compiler::general::{
    CompileMode, CompileRequest, CpuFeature, FeatureSet, OutputContract, Target, compile,
};

fn usage() -> &'static str {
    "usage: compile_general_aot PATTERN TARGET OUTPUT.o [fast|optimizing] \
     [span|end|exists] [FEATURES]\n\
     targets: linux-x86_64, macos-x86_64, linux-aarch64, macos-aarch64\n\
     FEATURES is a comma-separated set of: sse2,avx2,avx512f,avx512bw,avx512vl,\
     asimd,sve,sve2\n\
     x86-64 codegen: empty/sse2 => SSE2; avx2 => AVX2; \
     avx512f+avx512bw => AVX-512\n\
     AArch64 codegen: empty => scalar; asimd => ASIMD\n\
     accepted but currently non-selecting: avx512vl,sve,sve2\n\
     CPU features are explicit deployment facts; there is no host autodetection"
}

fn target(name: &str) -> Option<Target> {
    match name {
        "linux-x86_64" => Some(Target::x86_64_linux()),
        "macos-x86_64" => Some(Target::x86_64_macos()),
        "linux-aarch64" => Some(Target::aarch64_linux()),
        "macos-aarch64" => Some(Target::aarch64_macos()),
        _ => None,
    }
}

fn features(value: Option<&str>) -> Result<FeatureSet, String> {
    let Some(value) = value else {
        return Ok(FeatureSet::EMPTY);
    };
    if value.is_empty() || value == "none" {
        return Ok(FeatureSet::EMPTY);
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
            _ => return Err(usage().to_owned()),
        };
        features = features.with(feature);
    }
    Ok(features)
}

fn run() -> Result<(), String> {
    let mut arguments = env::args().skip(1);
    let pattern = arguments.next().ok_or_else(|| usage().to_owned())?;
    let target_name = arguments.next().ok_or_else(|| usage().to_owned())?;
    let output_path = arguments.next().ok_or_else(|| usage().to_owned())?;
    let mode = match arguments.next().as_deref().unwrap_or("optimizing") {
        "fast" => CompileMode::Fast,
        "optimizing" => CompileMode::Optimizing,
        _ => return Err(usage().to_owned()),
    };
    let output = match arguments.next().as_deref().unwrap_or("span") {
        "span" => OutputContract::Span,
        "end" => OutputContract::SelectedEnd,
        "exists" => OutputContract::Exists,
        _ => return Err(usage().to_owned()),
    };
    let features = features(arguments.next().as_deref())?;
    if arguments.next().is_some() {
        return Err(usage().to_owned());
    }
    let target = target(&target_name)
        .ok_or_else(|| usage().to_owned())?
        .with_features(features)
        .map_err(|error| error.to_string())?;
    let compiled = compile(
        CompileRequest::new(pattern, target)
            .mode(mode)
            .output(output),
    )
    .map_err(|error| error.to_string())?;
    fs::write(&output_path, compiled.object())
        .map_err(|error| format!("could not write {output_path}: {error}"))?;
    eprintln!("entry: {}", compiled.module().entry_symbol());
    if let Some(symbol) = compiled.module().required_runtime_symbol() {
        eprintln!("runtime helper: {symbol}");
    }
    if let Some((symbol, length)) = compiled.module().required_runtime_program() {
        eprintln!("runtime program: {symbol} ({length} bytes)");
    }
    eprintln!("receipt: {:#?}", compiled.receipt());
    Ok(())
}

fn main() -> ExitCode {
    match run() {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => {
            eprintln!("{error}");
            ExitCode::FAILURE
        }
    }
}
