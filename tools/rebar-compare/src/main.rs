use std::{env, fs, path::PathBuf, process::ExitCode};

use rebar_compare::{RunConfig, RunLimits, report_bytes, run};

fn main() -> ExitCode {
    match real_main() {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => {
            eprintln!("rebar-compare: {error}");
            ExitCode::FAILURE
        }
    }
}

fn real_main() -> Result<(), Box<dyn std::error::Error>> {
    let mut args = env::args_os().skip(1);
    let manifest = args.next().map(PathBuf::from).ok_or(
        "usage: rebar-compare MANIFEST REBAR_CHECKOUT OUTPUT [RUST_REBAR_RUNNER] [RE2_REBAR_RUNNER] [--no-fre]",
    )?;
    let checkout = args
        .next()
        .map(PathBuf::from)
        .ok_or("missing Rebar checkout")?;
    let output = args
        .next()
        .map(PathBuf::from)
        .ok_or("missing output path")?;
    let mut runner = None;
    let mut re2_runner = None;
    let mut run_fre = true;
    for argument in args {
        if argument == "--no-fre" {
            run_fre = false;
        } else if runner.is_none() {
            runner = Some(PathBuf::from(argument));
        } else if re2_runner.is_none() {
            re2_runner = Some(PathBuf::from(argument));
        } else {
            return Err("unexpected extra argument".into());
        }
    }
    let report = run(&RunConfig {
        manifest,
        checkout,
        rebar_rust_runner: runner,
        rebar_re2_runner: re2_runner,
        run_fre,
        limits: RunLimits::default(),
    })?;
    let bytes = report_bytes(&report)?;
    fs::write(output, bytes)?;
    Ok(())
}
