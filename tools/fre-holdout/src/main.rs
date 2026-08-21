use std::{env, path::PathBuf, process::ExitCode};

use fre_holdout::{
    AotSelectedEndComparisonStatus, AotSelectedEndDisposition, AotSelectedEndRunConfig,
    AotSelectedEndV2Eligibility, AotSelectedEndV2RunConfig, RunConfig, authenticate_paths,
    derive_digest_manifest, enforce_aot_selected_end_strict_gate,
    enforce_aot_selected_end_v2_strict_gate, enforce_strict_gate, run, run_aot_selected_end,
    run_aot_selected_end_v2_experiment,
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
        .ok_or("usage: fre-holdout derive SUITE SCHEMA | fre-holdout authenticate SUITE SCHEMA DIGESTS | fre-holdout run SUITE SCHEMA DIGESTS CORRECTNESS [--performance OUTPUT] | fre-holdout run-aot-selected-end SUITE SCHEMA DIGESTS CORRECTNESS [--performance OUTPUT] | fre-holdout run-aot-selected-end-v2-experiment SUITE SCHEMA DIGESTS CORRECTNESS [--performance OUTPUT]")?;
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
        "run-aot-selected-end" => run_aot_selected_end_command(&mut arguments)?,
        "run-aot-selected-end-v2-experiment" => {
            run_aot_selected_end_v2_experiment_command(&mut arguments)?;
        }
        other => return Err(format!("unknown command {other:?}").into()),
    }
    Ok(())
}

fn run_aot_selected_end_v2_experiment_command(
    arguments: &mut impl Iterator<Item = std::ffi::OsString>,
) -> Result<(), Box<dyn std::error::Error>> {
    let suite = next_path(arguments, "suite")?;
    let schema = next_path(arguments, "schema")?;
    let digests = next_path(arguments, "digests")?;
    let correctness_output = next_path(arguments, "correctness output")?;
    let performance_output = match arguments.next() {
        None => None,
        Some(flag) if flag == "--performance" => Some(next_path(arguments, "performance output")?),
        Some(other) => {
            return Err(format!("unexpected argument {}", PathBuf::from(other).display()).into());
        }
    };
    if arguments.next().is_some() {
        return Err("unexpected argument after output paths".into());
    }
    let report = run_aot_selected_end_v2_experiment(&AotSelectedEndV2RunConfig {
        suite,
        schema,
        digests,
        correctness_output,
        performance_output,
    })?;
    let ineligible = report
        .coverage
        .by_eligibility
        .get(&AotSelectedEndV2Eligibility::StructurallyIneligible)
        .copied()
        .unwrap_or(0);
    let declined = report
        .coverage
        .by_eligibility
        .get(&AotSelectedEndV2Eligibility::CompileDeclined)
        .copied()
        .unwrap_or(0);
    let faults = report
        .coverage
        .by_eligibility
        .get(&AotSelectedEndV2Eligibility::Fault)
        .copied()
        .unwrap_or(0);
    let failures = report
        .coverage
        .by_policy_input_status
        .values()
        .map(|statuses| {
            statuses
                .get(&AotSelectedEndComparisonStatus::Fail)
                .copied()
                .unwrap_or(0)
        })
        .sum::<usize>();
    println!(
        "suite={} v2_cases={} eligible={} ineligible={} declined={} fault={} eligible_windows={} policy_comparisons={} fail={} eligibility_sha256={} receipts_sha256={}",
        report.suite_id,
        report.coverage.case_patterns,
        report.coverage.frozen_eligible_cases,
        ineligible,
        declined,
        faults,
        report.coverage.frozen_eligible_search_windows,
        report.coverage.policy_comparisons,
        failures,
        report.eligibility_sha256,
        report.receipts_sha256,
    );
    enforce_aot_selected_end_v2_strict_gate(&report)?;
    Ok(())
}

fn run_aot_selected_end_command(
    arguments: &mut impl Iterator<Item = std::ffi::OsString>,
) -> Result<(), Box<dyn std::error::Error>> {
    let suite = next_path(arguments, "suite")?;
    let schema = next_path(arguments, "schema")?;
    let digests = next_path(arguments, "digests")?;
    let correctness_output = next_path(arguments, "correctness output")?;
    let performance_output = match arguments.next() {
        None => None,
        Some(flag) if flag == "--performance" => Some(next_path(arguments, "performance output")?),
        Some(other) => {
            return Err(format!("unexpected argument {}", PathBuf::from(other).display()).into());
        }
    };
    if arguments.next().is_some() {
        return Err("unexpected argument after output paths".into());
    }
    let report = run_aot_selected_end(&AotSelectedEndRunConfig {
        suite,
        schema,
        digests,
        correctness_output,
        performance_output,
    })?;
    println!(
        "suite={} aot_selected_end_cases={} ready={} declined={} fault={} source_inputs={} search_windows={} applicable_windows={} pass={} window_declined={} fail={} window_fault={} receipts_sha256={}",
        report.suite_id,
        report.coverage.case_patterns,
        report
            .coverage
            .by_case_disposition
            .get(&AotSelectedEndDisposition::Ready)
            .copied()
            .unwrap_or(0),
        report
            .coverage
            .by_case_disposition
            .get(&AotSelectedEndDisposition::Declined)
            .copied()
            .unwrap_or(0),
        report
            .coverage
            .by_case_disposition
            .get(&AotSelectedEndDisposition::Fault)
            .copied()
            .unwrap_or(0),
        report.coverage.expanded_inputs,
        report.coverage.search_windows,
        report.coverage.applicable_search_windows,
        report
            .coverage
            .by_input_status
            .get(&AotSelectedEndComparisonStatus::Pass)
            .copied()
            .unwrap_or(0),
        report
            .coverage
            .by_input_status
            .get(&AotSelectedEndComparisonStatus::Declined)
            .copied()
            .unwrap_or(0),
        report
            .coverage
            .by_input_status
            .get(&AotSelectedEndComparisonStatus::Fail)
            .copied()
            .unwrap_or(0),
        report
            .coverage
            .by_input_status
            .get(&AotSelectedEndComparisonStatus::Fault)
            .copied()
            .unwrap_or(0),
        report.receipts_sha256
    );
    enforce_aot_selected_end_strict_gate(&report)?;
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
