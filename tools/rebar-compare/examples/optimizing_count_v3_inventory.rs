use std::{env, fs, path::PathBuf, process::ExitCode};

use rebar_compare::{
    RunConfig, RunLimits, optimizing_count_v3::inventory_optimizing_count_v3,
    read_authenticated_report,
};

fn main() -> ExitCode {
    match real_main() {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => {
            eprintln!("optimizing-count-v3-inventory: {error}");
            ExitCode::FAILURE
        }
    }
}

fn real_main() -> Result<(), Box<dyn std::error::Error>> {
    let mut arguments = env::args_os().skip(1);
    let manifest = arguments.next().map(PathBuf::from).ok_or(
        "usage: optimizing_count_v3_inventory MANIFEST REBAR_CHECKOUT SEMANTIC_REPORT OUTPUT",
    )?;
    let checkout = arguments
        .next()
        .map(PathBuf::from)
        .ok_or("missing Rebar checkout")?;
    let semantic_path = arguments
        .next()
        .map(PathBuf::from)
        .ok_or("missing semantic report")?;
    let output = arguments
        .next()
        .map(PathBuf::from)
        .ok_or("missing output path")?;
    if arguments.next().is_some() {
        return Err("unexpected extra argument".into());
    }

    let semantic = read_authenticated_report(&semantic_path)?;
    let inventory = inventory_optimizing_count_v3(
        &RunConfig {
            manifest,
            checkout,
            rebar_rust_runner: None,
            rebar_re2_runner: None,
            run_fre: true,
            limits: RunLimits::default(),
        },
        &semantic,
    )?;
    let mut bytes = serde_json::to_vec_pretty(&inventory)?;
    bytes.push(b'\n');
    fs::write(output, bytes)?;
    Ok(())
}
