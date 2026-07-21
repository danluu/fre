use std::{env, path::PathBuf, process::ExitCode};

use rust_regex_conformance::{
    authenticate_candidate_source, build_adapter_report, build_doctest_report,
    build_feature_matrix_report, build_inventory, build_misc_regression_report,
    build_regex_automata_adapter_report, build_regex_automata_all_mode_look_report,
    build_regex_automata_ascii_word_look_report, build_regex_automata_corpus_report,
    build_regex_automata_look_mode_matrix, build_regex_automata_unicode_word_look_report,
    build_regex_syntax_corpus_report, build_replacement_api_report, build_searcher_api_report,
    load_executable_cases, read_adapter_report, read_doctest_report, read_feature_matrix_report,
    read_inventory, read_misc_regression_report, read_regex_automata_adapter_report,
    read_regex_automata_corpus_report, read_regex_automata_gap_assignment,
    read_regex_automata_look_mode_matrix, read_regex_syntax_corpus_report,
    read_replacement_api_report, read_searcher_api_report, schedule_regex_automata_gap,
    validate_regex_automata_all_mode_look_strict_gain,
    validate_regex_automata_ascii_word_look_strict_gain, validate_regex_automata_look_strict_gain,
    validate_regex_automata_strict_gain, validate_regex_automata_unicode_word_look_strict_gain,
    write_adapter_report, write_doctest_report, write_feature_matrix_report, write_inventory,
    write_misc_regression_report, write_regex_automata_adapter_report,
    write_regex_automata_corpus_report, write_regex_automata_gap_assignment,
    write_regex_automata_look_mode_matrix, write_regex_syntax_corpus_report,
    write_replacement_api_report, write_searcher_api_report,
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

#[allow(
    clippy::too_many_lines,
    reason = "keeping the complete explicit CLI command dispatch together is auditable"
)]
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
        "run-regex-syntax-corpus" => run_regex_syntax_corpus(&mut args)?,
        "verify-regex-syntax-corpus-report" => verify_regex_syntax_corpus_report(&mut args)?,
        "inventory-regex-automata-corpus" => inventory_regex_automata_corpus(&mut args)?,
        "verify-regex-automata-corpus-report" => {
            verify_regex_automata_corpus_report(&mut args)?;
        }
        "run-regex-automata-adapter" => run_regex_automata_adapter(&mut args)?,
        "run-regex-automata-look-mode-matrix" => {
            run_regex_automata_look_mode_matrix(&mut args)?;
        }
        "run-regex-automata-look-all-modes" => {
            run_regex_automata_look_all_modes(&mut args)?;
        }
        "run-regex-automata-look-ascii-word" => {
            run_regex_automata_look_ascii_word(&mut args)?;
        }
        "run-regex-automata-look-unicode-word" => {
            run_regex_automata_look_unicode_word(&mut args)?;
        }
        "schedule-regex-automata-gap" => schedule_regex_automata_assignment(&mut args)?,
        "verify-regex-automata-strict-gain" => verify_regex_automata_gain(&mut args)?,
        "verify-regex-automata-look-strict-gain" => {
            verify_regex_automata_look_gain(&mut args)?;
        }
        "verify-regex-automata-look-all-modes-strict-gain" => {
            verify_regex_automata_look_all_modes_gain(&mut args)?;
        }
        "verify-regex-automata-look-ascii-word-strict-gain" => {
            verify_regex_automata_look_ascii_word_gain(&mut args)?;
        }
        "verify-regex-automata-look-unicode-word-strict-gain" => {
            verify_regex_automata_look_unicode_word_gain(&mut args)?;
        }
        "-h" | "--help" | "help" => println!("{}", usage()),
        _ => return Err(usage().into()),
    }
    Ok(())
}

fn run_regex_automata_adapter(
    args: &mut impl Iterator<Item = String>,
) -> Result<(), Box<dyn std::error::Error>> {
    let inventory_path = PathBuf::from(args.next().ok_or(usage())?);
    let candidate_path = PathBuf::from(args.next().ok_or(usage())?);
    let output = PathBuf::from(args.next().ok_or(usage())?);
    reject_extra(args)?;
    let inventory = read_regex_automata_corpus_report(&inventory_path)?;
    let candidate = authenticate_candidate_source(&candidate_path)?;
    let report = build_regex_automata_adapter_report(&inventory, candidate)?;
    write_regex_automata_adapter_report(&output, &report, &inventory)?;
    println!(
        "regex-automata-adapter candidate={} pass={} unsupported={} fault={} total={} payload_sha256={}",
        report.payload.candidate.revision,
        report.payload.counts.pass,
        report.payload.counts.unsupported,
        report.payload.counts.fault,
        report.payload.counts.total,
        report.payload_sha256,
    );
    Ok(())
}

fn run_regex_automata_look_mode_matrix(
    args: &mut impl Iterator<Item = String>,
) -> Result<(), Box<dyn std::error::Error>> {
    let crate_archive = PathBuf::from(args.next().ok_or(usage())?);
    let upstream_package = PathBuf::from(args.next().ok_or(usage())?);
    let vcs_checkout = PathBuf::from(args.next().ok_or(usage())?);
    let inventory_path = PathBuf::from(args.next().ok_or(usage())?);
    let target_dir = PathBuf::from(args.next().ok_or(usage())?);
    let output = PathBuf::from(args.next().ok_or(usage())?);
    reject_extra(args)?;
    let inventory = read_regex_automata_corpus_report(&inventory_path)?;
    let matrix = build_regex_automata_look_mode_matrix(
        &crate_archive,
        &upstream_package,
        &vcs_checkout,
        &inventory,
        &target_dir,
    )?;
    write_regex_automata_look_mode_matrix(&output, &matrix)?;
    println!(
        "regex-automata-look-mode-matrix modes={} available={} unavailable={} memberships={} payload_sha256={}",
        matrix.payload.counts.modes,
        matrix.payload.counts.available_modes,
        matrix.payload.counts.unavailable_modes,
        matrix.payload.counts.available_test_memberships,
        matrix.payload_sha256,
    );
    Ok(())
}

fn run_regex_automata_look_all_modes(
    args: &mut impl Iterator<Item = String>,
) -> Result<(), Box<dyn std::error::Error>> {
    let inventory_path = PathBuf::from(args.next().ok_or(usage())?);
    let previous_path = PathBuf::from(args.next().ok_or(usage())?);
    let matrix_path = PathBuf::from(args.next().ok_or(usage())?);
    let candidate_path = PathBuf::from(args.next().ok_or(usage())?);
    let output = PathBuf::from(args.next().ok_or(usage())?);
    reject_extra(args)?;
    let inventory = read_regex_automata_corpus_report(&inventory_path)?;
    let previous = read_regex_automata_adapter_report(&previous_path, &inventory)?;
    let matrix = read_regex_automata_look_mode_matrix(&matrix_path)?;
    let candidate = authenticate_candidate_source(&candidate_path)?;
    let report =
        build_regex_automata_all_mode_look_report(&inventory, &previous, matrix, candidate)?;
    write_regex_automata_adapter_report(&output, &report, &inventory)?;
    println!(
        "regex-automata-look-all-modes candidate={} pass={} unsupported={} fault={} total={} payload_sha256={}",
        report.payload.candidate.revision,
        report.payload.counts.pass,
        report.payload.counts.unsupported,
        report.payload.counts.fault,
        report.payload.counts.total,
        report.payload_sha256,
    );
    Ok(())
}

fn run_regex_automata_look_ascii_word(
    args: &mut impl Iterator<Item = String>,
) -> Result<(), Box<dyn std::error::Error>> {
    let inventory_path = PathBuf::from(args.next().ok_or(usage())?);
    let previous_path = PathBuf::from(args.next().ok_or(usage())?);
    let candidate_path = PathBuf::from(args.next().ok_or(usage())?);
    let output = PathBuf::from(args.next().ok_or(usage())?);
    reject_extra(args)?;
    let inventory = read_regex_automata_corpus_report(&inventory_path)?;
    let previous = read_regex_automata_adapter_report(&previous_path, &inventory)?;
    let candidate = authenticate_candidate_source(&candidate_path)?;
    let report = build_regex_automata_ascii_word_look_report(&inventory, &previous, candidate)?;
    write_regex_automata_adapter_report(&output, &report, &inventory)?;
    println!(
        "regex-automata-look-ascii-word candidate={} pass={} unsupported={} fault={} total={} payload_sha256={}",
        report.payload.candidate.revision,
        report.payload.counts.pass,
        report.payload.counts.unsupported,
        report.payload.counts.fault,
        report.payload.counts.total,
        report.payload_sha256,
    );
    Ok(())
}

fn run_regex_automata_look_unicode_word(
    args: &mut impl Iterator<Item = String>,
) -> Result<(), Box<dyn std::error::Error>> {
    let inventory_path = PathBuf::from(args.next().ok_or(usage())?);
    let previous_path = PathBuf::from(args.next().ok_or(usage())?);
    let candidate_path = PathBuf::from(args.next().ok_or(usage())?);
    let output = PathBuf::from(args.next().ok_or(usage())?);
    reject_extra(args)?;
    let inventory = read_regex_automata_corpus_report(&inventory_path)?;
    let previous = read_regex_automata_adapter_report(&previous_path, &inventory)?;
    let candidate = authenticate_candidate_source(&candidate_path)?;
    let report = build_regex_automata_unicode_word_look_report(&inventory, &previous, candidate)?;
    write_regex_automata_adapter_report(&output, &report, &inventory)?;
    println!(
        "regex-automata-look-unicode-word candidate={} pass={} unsupported={} fault={} total={} payload_sha256={}",
        report.payload.candidate.revision,
        report.payload.counts.pass,
        report.payload.counts.unsupported,
        report.payload.counts.fault,
        report.payload.counts.total,
        report.payload_sha256,
    );
    Ok(())
}

fn schedule_regex_automata_assignment(
    args: &mut impl Iterator<Item = String>,
) -> Result<(), Box<dyn std::error::Error>> {
    let inventory_path = PathBuf::from(args.next().ok_or(usage())?);
    let baseline_path = PathBuf::from(args.next().ok_or(usage())?);
    let attempt_id = args.next().ok_or(usage())?;
    let slot = args
        .next()
        .ok_or(usage())?
        .parse::<usize>()
        .map_err(|_| "slot must be an unsigned integer")?;
    let output = PathBuf::from(args.next().ok_or(usage())?);
    reject_extra(args)?;
    let inventory = read_regex_automata_corpus_report(&inventory_path)?;
    let baseline = read_regex_automata_adapter_report(&baseline_path, &inventory)?;
    let assignment = schedule_regex_automata_gap(&inventory, &baseline, &attempt_id, slot)?;
    write_regex_automata_gap_assignment(&output, &assignment, &inventory, &baseline)?;
    println!(
        "regex-automata-gap attempt={} slot={} base={} family={} unique_cases={} targets_sha256={}",
        assignment.attempt_id,
        assignment.slot,
        assignment.base,
        assignment.family,
        assignment.targets.len(),
        assignment.targets_sha256,
    );
    Ok(())
}

fn verify_regex_automata_gain(
    args: &mut impl Iterator<Item = String>,
) -> Result<(), Box<dyn std::error::Error>> {
    let inventory_path = PathBuf::from(args.next().ok_or(usage())?);
    let previous_path = PathBuf::from(args.next().ok_or(usage())?);
    let current_path = PathBuf::from(args.next().ok_or(usage())?);
    let assignment_path = PathBuf::from(args.next().ok_or(usage())?);
    reject_extra(args)?;
    let inventory = read_regex_automata_corpus_report(&inventory_path)?;
    let previous = read_regex_automata_adapter_report(&previous_path, &inventory)?;
    let current = read_regex_automata_adapter_report(&current_path, &inventory)?;
    let assignment = read_regex_automata_gap_assignment(&assignment_path, &inventory, &previous)?;
    let gain = validate_regex_automata_strict_gain(&inventory, &previous, &current, &assignment)?;
    println!(
        "verified regex-automata-strict-gain family={} unique_cases={} mode_memberships={} previous_pass={} current_pass={}",
        gain.family,
        gain.gained_unique_cases,
        gain.gained_mode_memberships,
        gain.previous_pass,
        gain.current_pass,
    );
    Ok(())
}

fn verify_regex_automata_look_gain(
    args: &mut impl Iterator<Item = String>,
) -> Result<(), Box<dyn std::error::Error>> {
    let inventory_path = PathBuf::from(args.next().ok_or(usage())?);
    let previous_path = PathBuf::from(args.next().ok_or(usage())?);
    let current_path = PathBuf::from(args.next().ok_or(usage())?);
    reject_extra(args)?;
    let inventory = read_regex_automata_corpus_report(&inventory_path)?;
    let previous = read_regex_automata_adapter_report(&previous_path, &inventory)?;
    let current = read_regex_automata_adapter_report(&current_path, &inventory)?;
    let gain = validate_regex_automata_look_strict_gain(&inventory, &previous, &current)?;
    println!(
        "verified regex-automata-look-strict-gain family={} unique_cases={} mode_memberships={} previous_pass={} current_pass={}",
        gain.family,
        gain.gained_unique_cases,
        gain.gained_mode_memberships,
        gain.previous_pass,
        gain.current_pass,
    );
    Ok(())
}

fn verify_regex_automata_look_all_modes_gain(
    args: &mut impl Iterator<Item = String>,
) -> Result<(), Box<dyn std::error::Error>> {
    let inventory_path = PathBuf::from(args.next().ok_or(usage())?);
    let previous_path = PathBuf::from(args.next().ok_or(usage())?);
    let current_path = PathBuf::from(args.next().ok_or(usage())?);
    let candidate_path = PathBuf::from(args.next().ok_or(usage())?);
    reject_extra(args)?;
    let inventory = read_regex_automata_corpus_report(&inventory_path)?;
    let previous = read_regex_automata_adapter_report(&previous_path, &inventory)?;
    let current = read_regex_automata_adapter_report(&current_path, &inventory)?;
    let gain = validate_regex_automata_all_mode_look_strict_gain(
        &inventory,
        &previous,
        &current,
        &candidate_path,
    )?;
    println!(
        "verified regex-automata-look-all-modes-strict-gain family={} unique_cases={} mode_memberships={} previous_pass={} current_pass={}",
        gain.family,
        gain.gained_unique_cases,
        gain.gained_mode_memberships,
        gain.previous_pass,
        gain.current_pass,
    );
    Ok(())
}

fn verify_regex_automata_look_ascii_word_gain(
    args: &mut impl Iterator<Item = String>,
) -> Result<(), Box<dyn std::error::Error>> {
    let inventory_path = PathBuf::from(args.next().ok_or(usage())?);
    let previous_path = PathBuf::from(args.next().ok_or(usage())?);
    let current_path = PathBuf::from(args.next().ok_or(usage())?);
    reject_extra(args)?;
    let inventory = read_regex_automata_corpus_report(&inventory_path)?;
    let previous = read_regex_automata_adapter_report(&previous_path, &inventory)?;
    let current = read_regex_automata_adapter_report(&current_path, &inventory)?;
    let gain =
        validate_regex_automata_ascii_word_look_strict_gain(&inventory, &previous, &current)?;
    println!(
        "verified regex-automata-look-ascii-word-strict-gain family={} unique_cases={} mode_memberships={} previous_pass={} current_pass={}",
        gain.family,
        gain.gained_unique_cases,
        gain.gained_mode_memberships,
        gain.previous_pass,
        gain.current_pass,
    );
    Ok(())
}

fn verify_regex_automata_look_unicode_word_gain(
    args: &mut impl Iterator<Item = String>,
) -> Result<(), Box<dyn std::error::Error>> {
    let inventory_path = PathBuf::from(args.next().ok_or(usage())?);
    let previous_path = PathBuf::from(args.next().ok_or(usage())?);
    let current_path = PathBuf::from(args.next().ok_or(usage())?);
    reject_extra(args)?;
    let inventory = read_regex_automata_corpus_report(&inventory_path)?;
    let previous = read_regex_automata_adapter_report(&previous_path, &inventory)?;
    let current = read_regex_automata_adapter_report(&current_path, &inventory)?;
    let gain =
        validate_regex_automata_unicode_word_look_strict_gain(&inventory, &previous, &current)?;
    println!(
        "verified regex-automata-look-unicode-word-strict-gain family={} unique_cases={} mode_memberships={} previous_pass={} current_pass={}",
        gain.family,
        gain.gained_unique_cases,
        gain.gained_mode_memberships,
        gain.previous_pass,
        gain.current_pass,
    );
    Ok(())
}

fn inventory_regex_automata_corpus(
    args: &mut impl Iterator<Item = String>,
) -> Result<(), Box<dyn std::error::Error>> {
    let crate_archive = PathBuf::from(args.next().ok_or(usage())?);
    let upstream_package = PathBuf::from(args.next().ok_or(usage())?);
    let vcs_checkout = PathBuf::from(args.next().ok_or(usage())?);
    let target_dir = PathBuf::from(args.next().ok_or(usage())?);
    let output = PathBuf::from(args.next().ok_or(usage())?);
    reject_extra(args)?;
    let report = build_regex_automata_corpus_report(
        &crate_archive,
        &upstream_package,
        &vcs_checkout,
        &target_dir,
    )?;
    write_regex_automata_corpus_report(&output, &report)?;
    let counts = &report.payload.counts;
    println!(
        "regex-automata-corpus modes={} mode_members={} unique_members={} fre_pass={} unsupported={} inventory_sha256={} payload_sha256={}",
        counts.feature_modes,
        counts.total_mode_members,
        counts.unique_members,
        counts.fre_pass,
        counts.unsupported,
        report.payload.harness.obligation_inventory_sha256,
        report.payload_sha256,
    );
    Ok(())
}

fn verify_regex_automata_corpus_report(
    args: &mut impl Iterator<Item = String>,
) -> Result<(), Box<dyn std::error::Error>> {
    let report_path = PathBuf::from(args.next().ok_or(usage())?);
    reject_extra(args)?;
    let report = read_regex_automata_corpus_report(&report_path)?;
    let counts = &report.payload.counts;
    println!(
        "verified regex-automata-corpus modes={} mode_members={} unique_members={} fre_pass={} unsupported={} inventory_sha256={} payload_sha256={}",
        counts.feature_modes,
        counts.total_mode_members,
        counts.unique_members,
        counts.fre_pass,
        counts.unsupported,
        report.payload.harness.obligation_inventory_sha256,
        report.payload_sha256,
    );
    Ok(())
}

fn run_regex_syntax_corpus(
    args: &mut impl Iterator<Item = String>,
) -> Result<(), Box<dyn std::error::Error>> {
    let upstream_package = PathBuf::from(args.next().ok_or(usage())?);
    let candidate_path = PathBuf::from(args.next().ok_or(usage())?);
    let target_dir = PathBuf::from(args.next().ok_or(usage())?);
    let output = PathBuf::from(args.next().ok_or(usage())?);
    reject_extra(args)?;
    let report = build_regex_syntax_corpus_report(&upstream_package, &candidate_path, &target_dir)?;
    write_regex_syntax_corpus_report(&output, &report)?;
    let counts = &report.payload.counts;
    println!(
        "regex-syntax-corpus candidate={} pass={} mismatch={} unsupported={} fault={} total={} upstream_oracle_pass={} upstream_oracle_mismatch={} upstream_oracle_fault={} inventory_sha256={} payload_sha256={}",
        report.payload.candidate.revision,
        counts.pass,
        counts.mismatch,
        counts.unsupported,
        counts.fault,
        counts.total,
        report.payload.upstream_oracle.counts.pass,
        report.payload.upstream_oracle.counts.mismatch,
        report.payload.upstream_oracle.counts.fault,
        report.payload.harness.obligation_inventory_sha256,
        report.payload_sha256
    );
    Ok(())
}

fn verify_regex_syntax_corpus_report(
    args: &mut impl Iterator<Item = String>,
) -> Result<(), Box<dyn std::error::Error>> {
    let report_path = PathBuf::from(args.next().ok_or(usage())?);
    reject_extra(args)?;
    let report = read_regex_syntax_corpus_report(&report_path)?;
    let counts = &report.payload.counts;
    println!(
        "verified regex-syntax-corpus candidate={} pass={} mismatch={} unsupported={} fault={} total={} upstream_oracle_pass={} upstream_oracle_mismatch={} upstream_oracle_fault={} inventory_sha256={} payload_sha256={}",
        report.payload.candidate.revision,
        counts.pass,
        counts.mismatch,
        counts.unsupported,
        counts.fault,
        counts.total,
        report.payload.upstream_oracle.counts.pass,
        report.payload.upstream_oracle.counts.mismatch,
        report.payload.upstream_oracle.counts.fault,
        report.payload.harness.obligation_inventory_sha256,
        report.payload_sha256
    );
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
    "usage: rust-regex-conformance generate CHECKOUT OUTPUT | verify CHECKOUT MANIFEST | validate MANIFEST | run CHECKOUT MANIFEST CANDIDATE_REPO OUTPUT | verify-report MANIFEST REPORT | run-replacement-api UPSTREAM_PACKAGE CANDIDATE_REPO OUTPUT | verify-replacement-api-report REPORT | run-searcher-api UPSTREAM_PACKAGE CANDIDATE_REPO OUTPUT | verify-searcher-api-report REPORT | run-misc-regression-api UPSTREAM_PACKAGE CANDIDATE_REPO OUTPUT | verify-misc-regression-api-report REPORT | run-feature-matrix UPSTREAM_PACKAGE CANDIDATE_REPO TARGET_DIR OUTPUT | verify-feature-matrix-report REPORT | run-doctest-api UPSTREAM_PACKAGE CANDIDATE_REPO OUTPUT | verify-doctest-api-report REPORT | run-regex-syntax-corpus UPSTREAM_PACKAGE CANDIDATE_REPO TARGET_DIR OUTPUT | verify-regex-syntax-corpus-report REPORT | inventory-regex-automata-corpus CRATE_ARCHIVE UPSTREAM_PACKAGE VCS_CHECKOUT TARGET_DIR OUTPUT | verify-regex-automata-corpus-report REPORT | run-regex-automata-adapter INVENTORY CANDIDATE_REPO OUTPUT | run-regex-automata-look-mode-matrix CRATE_ARCHIVE UPSTREAM_PACKAGE VCS_CHECKOUT INVENTORY TARGET_DIR OUTPUT | run-regex-automata-look-all-modes INVENTORY PREVIOUS_REPORT MATRIX CANDIDATE_REPO OUTPUT | run-regex-automata-look-ascii-word INVENTORY PREVIOUS_REPORT CANDIDATE_REPO OUTPUT | run-regex-automata-look-unicode-word INVENTORY PREVIOUS_REPORT CANDIDATE_REPO OUTPUT | schedule-regex-automata-gap INVENTORY BASELINE_REPORT ATTEMPT SLOT OUTPUT | verify-regex-automata-strict-gain INVENTORY PREVIOUS_REPORT CURRENT_REPORT ASSIGNMENT | verify-regex-automata-look-strict-gain INVENTORY PREVIOUS_REPORT CURRENT_REPORT | verify-regex-automata-look-all-modes-strict-gain INVENTORY PREVIOUS_REPORT CURRENT_REPORT CANDIDATE_REPO | verify-regex-automata-look-ascii-word-strict-gain INVENTORY PREVIOUS_REPORT CURRENT_REPORT | verify-regex-automata-look-unicode-word-strict-gain INVENTORY PREVIOUS_REPORT CURRENT_REPORT"
}
