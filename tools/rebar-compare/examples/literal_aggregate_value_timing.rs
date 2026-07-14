use std::{env, fs, path::PathBuf, process::ExitCode};

use rebar_compare::{
    RunConfig, RunLimits, read_authenticated_report, time_literal_aggregate_value_receipts,
};

fn main() -> ExitCode {
    match real_main() {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => {
            eprintln!("literal-aggregate-value-timing: {error}");
            ExitCode::FAILURE
        }
    }
}

fn parse_usize(value: Option<std::ffi::OsString>, default: usize) -> Result<usize, String> {
    let Some(value) = value else {
        return Ok(default);
    };
    value
        .to_str()
        .ok_or_else(|| "numeric timing argument is not UTF-8".to_string())?
        .parse::<usize>()
        .map_err(|error| format!("invalid numeric timing argument: {error}"))
}

fn real_main() -> Result<(), Box<dyn std::error::Error>> {
    let mut args = env::args_os().skip(1);
    let manifest = args.next().map(PathBuf::from).ok_or(
        "usage: literal_aggregate_value_timing MANIFEST REBAR_CHECKOUT SEMANTIC_REPORT OUTPUT [SAMPLES] [TARGET_BYTES] [MAX_ITERATIONS]",
    )?;
    let checkout = args
        .next()
        .map(PathBuf::from)
        .ok_or("missing Rebar checkout")?;
    let semantic_path = args
        .next()
        .map(PathBuf::from)
        .ok_or("missing semantic report")?;
    let output = args
        .next()
        .map(PathBuf::from)
        .ok_or("missing timing output")?;
    let samples = parse_usize(args.next(), 9)?;
    let target_bytes = parse_usize(args.next(), 16 * 1_048_576)?;
    let max_iterations = parse_usize(args.next(), 100_000)?;
    if args.next().is_some() {
        return Err("unexpected extra argument".into());
    }

    let semantic = read_authenticated_report(&semantic_path)?;
    let report = time_literal_aggregate_value_receipts(
        &RunConfig {
            manifest,
            checkout,
            rebar_rust_runner: None,
            rebar_re2_runner: None,
            run_fre: true,
            limits: RunLimits::default(),
        },
        &semantic,
        samples,
        target_bytes,
        max_iterations,
    )?;
    let mut bytes = serde_json::to_vec_pretty(&report)?;
    bytes.push(b'\n');
    fs::write(output, bytes)?;
    Ok(())
}
