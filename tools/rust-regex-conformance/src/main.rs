use std::{env, path::PathBuf, process::ExitCode};

use rust_regex_conformance::{
    authenticate_candidate_source, build_adapter_report, build_doctest_report,
    build_feature_matrix_report, build_inventory, build_misc_regression_report,
    build_replacement_api_report, build_searcher_api_report, load_executable_cases,
    read_adapter_report, read_doctest_report, read_feature_matrix_report, read_inventory,
    read_misc_regression_report, read_replacement_api_report, read_searcher_api_report,
    write_adapter_report, write_doctest_report, write_feature_matrix_report, write_inventory,
    write_misc_regression_report, write_replacement_api_report, write_searcher_api_report,
};

fn main() -> ExitCode {
    match run() {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => {
            eprintln!("rust-regex-conformance: {error}");
            ExitCode::FAILURE
        }
    }
}

fn run() -> Result<(), Box<dyn std::error::Error>> {
    let mut args = env::args().skip(1);
    let command = args.next().ok_or(usage())?;
    match command.as_str() {
        "generate" => {
            let checkout = PathBuf::from(args.next().ok_or(usage())?);
            let output = PathBuf::from(args.next().ok_or(usage())?);
            reject_extra(&mut args)?;
            let inventory = build_inventory(&checkout)?;
            write_inventory(&output, &inventory)?;
            println!(
                "inventory revision={} files={} raw_cases={} rust_regex_cases={} obligations={} payload_sha256={}",
                inventory.payload.upstream.revision,
                inventory.payload.scope.source_files,
                inventory.payload.scope.raw_cases,
                inventory.payload.scope.rust_regex_cases,
                inventory.payload.scope.adapter_obligations,
                inventory.payload_sha256
            );
        }
        "verify" => {
            let checkout = PathBuf::from(args.next().ok_or(usage())?);
            let manifest_path = PathBuf::from(args.next().ok_or(usage())?);
            reject_extra(&mut args)?;
            let expected = read_inventory(&manifest_path)?;
            let actual = build_inventory(&checkout)?;
            if actual != expected {
                return Err(
                    "checked-in manifest differs from authenticated upstream source".into(),
                );
            }
            println!(
                "verified revision={} files={} raw_cases={} rust_regex_cases={} payload_sha256={}",
                actual.payload.upstream.revision,
                actual.payload.scope.source_files,
                actual.payload.scope.raw_cases,
                actual.payload.scope.rust_regex_cases,
                actual.payload_sha256
            );
        }
        "validate" => {
            let manifest_path = PathBuf::from(args.next().ok_or(usage())?);
            reject_extra(&mut args)?;
            let inventory = read_inventory(&manifest_path)?;
            println!(
                "valid files={} raw_cases={} rust_regex_cases={} obligations={} payload_sha256={}",
                inventory.payload.scope.source_files,
                inventory.payload.scope.raw_cases,
                inventory.payload.scope.rust_regex_cases,
                inventory.payload.scope.adapter_obligations,
                inventory.payload_sha256
            );
        }
        "run" => {
            let checkout = PathBuf::from(args.next().ok_or(usage())?);
            let manifest_path = PathBuf::from(args.next().ok_or(usage())?);
            let candidate_path = PathBuf::from(args.next().ok_or(usage())?);
            let output = PathBuf::from(args.next().ok_or(usage())?);
            reject_extra(&mut args)?;
            let inventory = read_inventory(&manifest_path)?;
            let executable_cases = load_executable_cases(&checkout, &inventory)?;
            let candidate = authenticate_candidate_source(&candidate_path)?;
            let report = build_adapter_report(&inventory, executable_cases, candidate)?;
            write_adapter_report(&output, &report, &inventory)?;
            let counts = &report.payload.counts;
            println!(
                "adapter candidate={} tree={} pass={} mismatch={} unsupported={} not_applicable={} fault={} total={} payload_sha256={}",
                report.payload.candidate.revision,
                report.payload.candidate.tree,
                counts.pass,
                counts.mismatch,
                counts.unsupported,
                counts.not_applicable,
                counts.fault,
                counts.total,
                report.payload_sha256
            );
        }
        "verify-report" => verify_adapter_report(&mut args)?,
        "run-replacement-api" => run_replacement_api(&mut args)?,
        "verify-replacement-api-report" => verify_replacement_api_report(&mut args)?,
        "run-misc-regression-api" => run_misc_regression_api(&mut args)?,
        "verify-misc-regression-api-report" => verify_misc_regression_api_report(&mut args)?,
        "run-feature-matrix" => run_feature_matrix(&mut args)?,
        "verify-feature-matrix-report" => verify_feature_matrix_report(&mut args)?,
        "run-searcher-api" => run_searcher_api(&mut args)?,
        "verify-searcher-api-report" => verify_searcher_api_report(&mut args)?,
        "run-doctest-api" => run_doctest_api(&mut args)?,
        "verify-doctest-api-report" => verify_doctest_api_report(&mut args)?,
        "-h" | "--help" | "help" => println!("{}", usage()),
        _ => return Err(usage().into()),
    }
    Ok(())
}

fn run_feature_matrix(
    args: &mut impl Iterator<Item = String>,
) -> Result<(), Box<dyn std::error::Error>> {
    let upstream_package = PathBuf::from(args.next().ok_or(usage())?);
    let candidate_path = PathBuf::from(args.next().ok_or(usage())?);
    let target_dir = PathBuf::from(args.next().ok_or(usage())?);
    let output = PathBuf::from(args.next().ok_or(usage())?);
    reject_extra(args)?;
    let report = build_feature_matrix_report(&upstream_package, &candidate_path, &target_dir)?;
    write_feature_matrix_report(&output, &report)?;
    let counts = &report.payload.counts;
    println!(
        "feature-matrix candidate={} pass={} unsupported_profile={} unsupported_toolchain={} unsupported_api={} fault={} total={} payload_sha256={}",
        report.payload.candidate.revision,
        counts.pass,
        counts.unsupported_profile,
        counts.unsupported_toolchain,
        counts.unsupported_api,
        counts.fault,
        counts.total,
        report.payload_sha256
    );
    if counts.fault != 0 {
        return Err("feature matrix contains fault dispositions".into());
    }
    Ok(())
}

fn verify_feature_matrix_report(
    args: &mut impl Iterator<Item = String>,
) -> Result<(), Box<dyn std::error::Error>> {
    let report_path = PathBuf::from(args.next().ok_or(usage())?);
    reject_extra(args)?;
    let report = read_feature_matrix_report(&report_path)?;
    let counts = &report.payload.counts;
    println!(
        "verified feature-matrix candidate={} pass={} unsupported_profile={} unsupported_toolchain={} unsupported_api={} fault={} total={} payload_sha256={}",
        report.payload.candidate.revision,
        counts.pass,
        counts.unsupported_profile,
        counts.unsupported_toolchain,
        counts.unsupported_api,
        counts.fault,
        counts.total,
        report.payload_sha256
    );
    if counts.fault != 0 {
        return Err("feature matrix contains fault dispositions".into());
    }
    Ok(())
}

fn run_doctest_api(
    args: &mut impl Iterator<Item = String>,
) -> Result<(), Box<dyn std::error::Error>> {
    let upstream_package = PathBuf::from(args.next().ok_or(usage())?);
    let candidate_path = PathBuf::from(args.next().ok_or(usage())?);
    let output = PathBuf::from(args.next().ok_or(usage())?);
    reject_extra(args)?;
    let candidate = authenticate_candidate_source(&candidate_path)?;
    let report = build_doctest_report(&upstream_package, candidate)?;
    write_doctest_report(&output, &report)?;
    let counts = &report.payload.counts;
    println!(
        "doctest-api candidate={} pass={} mismatch={} unsupported={} fault={} total={} inventory_sha256={} payload_sha256={}",
        report.payload.candidate.revision,
        counts.pass,
        counts.mismatch,
        counts.unsupported,
        counts.fault,
        counts.total,
        report.payload.source.obligation_inventory_sha256,
        report.payload_sha256
    );
    Ok(())
}

fn verify_doctest_api_report(
    args: &mut impl Iterator<Item = String>,
) -> Result<(), Box<dyn std::error::Error>> {
    let report_path = PathBuf::from(args.next().ok_or(usage())?);
    reject_extra(args)?;
    let report = read_doctest_report(&report_path)?;
    let counts = &report.payload.counts;
    println!(
        "verified doctest-api candidate={} pass={} mismatch={} unsupported={} fault={} total={} inventory_sha256={} payload_sha256={}",
        report.payload.candidate.revision,
        counts.pass,
        counts.mismatch,
        counts.unsupported,
        counts.fault,
        counts.total,
        report.payload.source.obligation_inventory_sha256,
        report.payload_sha256
    );
    Ok(())
}

fn run_misc_regression_api(
    args: &mut impl Iterator<Item = String>,
) -> Result<(), Box<dyn std::error::Error>> {
    let upstream_package = PathBuf::from(args.next().ok_or(usage())?);
    let candidate_path = PathBuf::from(args.next().ok_or(usage())?);
    let output = PathBuf::from(args.next().ok_or(usage())?);
    reject_extra(args)?;
    let candidate = authenticate_candidate_source(&candidate_path)?;
    let report = build_misc_regression_report(&upstream_package, candidate)?;
    write_misc_regression_report(&output, &report)?;
    let counts = &report.payload.counts;
    println!(
        "misc-regression-api candidate={} pass={} mismatch={} unsupported={} fault={} total={} payload_sha256={}",
        report.payload.candidate.revision,
        counts.pass,
        counts.mismatch,
        counts.unsupported,
        counts.fault,
        counts.total,
        report.payload_sha256
    );
    Ok(())
}

fn verify_misc_regression_api_report(
    args: &mut impl Iterator<Item = String>,
) -> Result<(), Box<dyn std::error::Error>> {
    let report_path = PathBuf::from(args.next().ok_or(usage())?);
    reject_extra(args)?;
    let report = read_misc_regression_report(&report_path)?;
    let counts = &report.payload.counts;
    println!(
        "verified misc-regression-api candidate={} pass={} mismatch={} unsupported={} fault={} total={} payload_sha256={}",
        report.payload.candidate.revision,
        counts.pass,
        counts.mismatch,
        counts.unsupported,
        counts.fault,
        counts.total,
        report.payload_sha256
    );
    Ok(())
}

fn verify_adapter_report(
    args: &mut impl Iterator<Item = String>,
) -> Result<(), Box<dyn std::error::Error>> {
    let manifest_path = PathBuf::from(args.next().ok_or(usage())?);
    let report_path = PathBuf::from(args.next().ok_or(usage())?);
    reject_extra(args)?;
    let inventory = read_inventory(&manifest_path)?;
    let report = read_adapter_report(&report_path, &inventory)?;
    let counts = &report.payload.counts;
    println!(
        "verified adapter candidate={} pass={} mismatch={} unsupported={} not_applicable={} fault={} total={} payload_sha256={}",
        report.payload.candidate.revision,
        counts.pass,
        counts.mismatch,
        counts.unsupported,
        counts.not_applicable,
        counts.fault,
        counts.total,
        report.payload_sha256
    );
    Ok(())
}

fn run_replacement_api(
    args: &mut impl Iterator<Item = String>,
) -> Result<(), Box<dyn std::error::Error>> {
    let upstream_package = PathBuf::from(args.next().ok_or(usage())?);
    let candidate_path = PathBuf::from(args.next().ok_or(usage())?);
    let output = PathBuf::from(args.next().ok_or(usage())?);
    reject_extra(args)?;
    let candidate = authenticate_candidate_source(&candidate_path)?;
    let report = build_replacement_api_report(&upstream_package, candidate)?;
    write_replacement_api_report(&output, &report)?;
    let counts = &report.payload.counts;
    println!(
        "replacement-api candidate={} pass={} mismatch={} unsupported={} fault={} total={} payload_sha256={}",
        report.payload.candidate.revision,
        counts.pass,
        counts.mismatch,
        counts.unsupported,
        counts.fault,
        counts.total,
        report.payload_sha256
    );
    Ok(())
}

fn verify_replacement_api_report(
    args: &mut impl Iterator<Item = String>,
) -> Result<(), Box<dyn std::error::Error>> {
    let report_path = PathBuf::from(args.next().ok_or(usage())?);
    reject_extra(args)?;
    let report = read_replacement_api_report(&report_path)?;
    let counts = &report.payload.counts;
    println!(
        "verified replacement-api candidate={} pass={} mismatch={} unsupported={} fault={} total={} payload_sha256={}",
        report.payload.candidate.revision,
        counts.pass,
        counts.mismatch,
        counts.unsupported,
        counts.fault,
        counts.total,
        report.payload_sha256
    );
    Ok(())
}

fn run_searcher_api(
    args: &mut impl Iterator<Item = String>,
) -> Result<(), Box<dyn std::error::Error>> {
    let upstream_package = PathBuf::from(args.next().ok_or(usage())?);
    let candidate_path = PathBuf::from(args.next().ok_or(usage())?);
    let output = PathBuf::from(args.next().ok_or(usage())?);
    reject_extra(args)?;
    let candidate = authenticate_candidate_source(&candidate_path)?;
    let report = build_searcher_api_report(&upstream_package, candidate)?;
    write_searcher_api_report(&output, &report)?;
    let counts = &report.payload.counts;
    println!(
        "searcher-api candidate={} pass={} mismatch={} unsupported={} fault={} total={} payload_sha256={}",
        report.payload.candidate.revision,
        counts.pass,
        counts.mismatch,
        counts.unsupported,
        counts.fault,
        counts.total,
        report.payload_sha256
    );
    Ok(())
}

fn verify_searcher_api_report(
    args: &mut impl Iterator<Item = String>,
) -> Result<(), Box<dyn std::error::Error>> {
    let report_path = PathBuf::from(args.next().ok_or(usage())?);
    reject_extra(args)?;
    let report = read_searcher_api_report(&report_path)?;
    let counts = &report.payload.counts;
    println!(
        "verified searcher-api candidate={} pass={} mismatch={} unsupported={} fault={} total={} payload_sha256={}",
        report.payload.candidate.revision,
        counts.pass,
        counts.mismatch,
        counts.unsupported,
        counts.fault,
        counts.total,
        report.payload_sha256
    );
    Ok(())
}

fn reject_extra(args: &mut impl Iterator<Item = String>) -> Result<(), String> {
    if let Some(extra) = args.next() {
        Err(format!("unexpected argument {extra:?}; {}", usage()))
    } else {
        Ok(())
    }
}

fn usage() -> &'static str {
    "usage: rust-regex-conformance generate CHECKOUT OUTPUT | verify CHECKOUT MANIFEST | validate MANIFEST | run CHECKOUT MANIFEST CANDIDATE_REPO OUTPUT | verify-report MANIFEST REPORT | run-replacement-api UPSTREAM_PACKAGE CANDIDATE_REPO OUTPUT | verify-replacement-api-report REPORT | run-searcher-api UPSTREAM_PACKAGE CANDIDATE_REPO OUTPUT | verify-searcher-api-report REPORT | run-misc-regression-api UPSTREAM_PACKAGE CANDIDATE_REPO OUTPUT | verify-misc-regression-api-report REPORT | run-feature-matrix UPSTREAM_PACKAGE CANDIDATE_REPO TARGET_DIR OUTPUT | verify-feature-matrix-report REPORT | run-doctest-api UPSTREAM_PACKAGE CANDIDATE_REPO OUTPUT | verify-doctest-api-report REPORT"
}
