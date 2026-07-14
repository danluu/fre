use std::{env, path::PathBuf, process::ExitCode};

use rebar_expand::{AUDITED_REBAR_REVISION, ExpandConfig, Limits, expand, write_output};

fn main() -> ExitCode {
    match run() {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => {
            eprintln!("rebar-expand: {error}");
            ExitCode::FAILURE
        }
    }
}

fn run() -> Result<(), Box<dyn std::error::Error>> {
    let mut checkout = PathBuf::from("/tmp/rebar-fre");
    let mut output = PathBuf::from("research/rebar/expanded");
    let mut rebar_bin = PathBuf::from("target/debug/rebar");
    let mut expected_revision = AUDITED_REBAR_REVISION.to_string();
    let mut args = env::args().skip(1);
    while let Some(arg) = args.next() {
        match arg.as_str() {
            "--checkout" => checkout = PathBuf::from(required_value(&mut args, &arg)?),
            "--output" => output = PathBuf::from(required_value(&mut args, &arg)?),
            "--rebar-bin" => rebar_bin = PathBuf::from(required_value(&mut args, &arg)?),
            "--expected-revision" => expected_revision = required_value(&mut args, &arg)?,
            "-h" | "--help" => {
                println!(
                    "Usage: rebar-expand [--checkout PATH] [--output PATH] \\\n+                     [--rebar-bin PATH] [--expected-revision HASH]"
                );
                return Ok(());
            }
            _ => return Err(format!("unexpected argument {arg:?}").into()),
        }
    }
    let config = ExpandConfig {
        checkout,
        rebar_bin,
        expected_revision,
        limits: Limits::default(),
    };
    let (manifest, blobs) = expand(&config)?;
    write_output(&output, &manifest, &blobs)?;
    println!(
        "expanded {} jobs from {} definition files into {}",
        manifest.scope.job_count,
        manifest.scope.definition_file_count,
        output.display()
    );
    Ok(())
}

fn required_value(args: &mut impl Iterator<Item = String>, flag: &str) -> Result<String, String> {
    args.next()
        .ok_or_else(|| format!("{flag} requires a value"))
}
