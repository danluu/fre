use std::{env, fs, path::PathBuf, process::ExitCode};

use rebar_compare::{RunConfig, RunLimits, run_unicode_literal_sentinel};

fn main() -> ExitCode {
    match real_main() {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => {
            eprintln!("unicode-literal-sentinel: {error}");
            ExitCode::FAILURE
        }
    }
}

fn real_main() -> Result<(), Box<dyn std::error::Error>> {
    let mut args = env::args_os().skip(1);
    let manifest = args
        .next()
        .map(PathBuf::from)
        .ok_or("usage: unicode_literal_sentinel MANIFEST REBAR_CHECKOUT BASELINE_REPORT OUTPUT")?;
    let checkout = args
        .next()
        .map(PathBuf::from)
        .ok_or("missing Rebar checkout")?;
    let baseline = args
        .next()
        .map(PathBuf::from)
        .ok_or("missing authenticated baseline report")?;
    let output = args
        .next()
        .map(PathBuf::from)
        .ok_or("missing output path")?;
    if args.next().is_some() {
        return Err("unexpected extra argument".into());
    }

    let report = run_unicode_literal_sentinel(
        &RunConfig {
            manifest,
            checkout,
            rebar_rust_runner: None,
            rebar_re2_runner: None,
            run_fre: true,
            limits: RunLimits::default(),
        },
        &baseline,
    )?;
    let mut bytes = serde_json::to_vec_pretty(&report)?;
    bytes.push(b'\n');
    fs::write(output, bytes)?;
    Ok(())
}
