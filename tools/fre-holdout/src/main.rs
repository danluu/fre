use std::{env, path::PathBuf, process::ExitCode};

use fre_holdout::{
    RunConfig, authenticate_paths, derive_digest_manifest, enforce_strict_gate, run,
};

fn main() -> ExitCode {
    match real_main() {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => {
            eprintln!("fre-holdout: {error}");
            ExitCode::FAILURE
        }
    }
}

fn real_main() -> Result<(), Box<dyn std::error::Error>> {
    let mut arguments = env::args_os().skip(1);
    let command = arguments
        .next()
        .ok_or("usage: fre-holdout derive SUITE SCHEMA | fre-holdout authenticate SUITE SCHEMA DIGESTS | fre-holdout run SUITE SCHEMA DIGESTS CORRECTNESS [--performance OUTPUT]")?;
    match command.to_string_lossy().as_ref() {
        "derive" => {
            let suite = next_path(&mut arguments, "suite")?;
            let schema = next_path(&mut arguments, "schema")?;
            if arguments.next().is_some() {
                return Err("unexpected argument after schema path".into());
            }
            let suite_bytes = std::fs::read(&suite)?;
            let schema_bytes = std::fs::read(&schema)?;
            let digests = derive_digest_manifest(&suite_bytes, &schema_bytes)?;
            println!("{}", serde_json::to_string_pretty(&digests)?);
        }
        "authenticate" => {
            let suite = next_path(&mut arguments, "suite")?;
            let schema = next_path(&mut arguments, "schema")?;
            let digests = next_path(&mut arguments, "digests")?;
            if arguments.next().is_some() {
                return Err("unexpected argument after digest path".into());
            }
            let authenticated = authenticate_paths(&suite, &schema, &digests)?;
            println!(
                "authenticated suite={} cases={} inputs={} digest={}",
                authenticated.manifest.suite_id,
                authenticated.manifest.cases.len(),
                authenticated.inputs.len(),
                authenticated.expanded_inputs_sha256
            );
        }
        "run" => {
            let suite = next_path(&mut arguments, "suite")?;
            let schema = next_path(&mut arguments, "schema")?;
            let digests = next_path(&mut arguments, "digests")?;
            let correctness_output = next_path(&mut arguments, "correctness output")?;
            let performance_output = match arguments.next() {
                None => None,
                Some(flag) if flag == "--performance" => {
                    Some(next_path(&mut arguments, "performance output")?)
                }
                Some(other) => {
                    return Err(
                        format!("unexpected argument {}", PathBuf::from(other).display()).into(),
                    );
                }
            };
            if arguments.next().is_some() {
                return Err("unexpected argument after output paths".into());
            }
            let report = run(&RunConfig {
                suite,
                schema,
                digests,
                correctness_output,
                performance_output,
            })?;
            println!(
                "suite={} receipts={} pass={} unsupported={} fail={} fault={} receipts_sha256={}",
                report.suite_id,
                report.coverage.receipts,
                report
                    .coverage
                    .by_status
                    .get(&fre_holdout::Status::Pass)
                    .copied()
                    .unwrap_or(0),
                report
                    .coverage
                    .by_status
                    .get(&fre_holdout::Status::Unsupported)
                    .copied()
                    .unwrap_or(0),
                report
                    .coverage
                    .by_status
                    .get(&fre_holdout::Status::Fail)
                    .copied()
                    .unwrap_or(0),
                report
                    .coverage
                    .by_status
                    .get(&fre_holdout::Status::Fault)
                    .copied()
                    .unwrap_or(0),
                report.receipts_sha256
            );
            enforce_strict_gate(&report)?;
        }
        other => return Err(format!("unknown command {other:?}").into()),
    }
    Ok(())
}

fn next_path(
    arguments: &mut impl Iterator<Item = std::ffi::OsString>,
    name: &str,
) -> Result<PathBuf, Box<dyn std::error::Error>> {
    arguments
        .next()
        .map(PathBuf::from)
        .ok_or_else(|| format!("missing {name} path").into())
}
