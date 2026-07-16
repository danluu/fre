use std::{env, fs, path::PathBuf, process::ExitCode};

use rebar_compare::performance_contract::{
    generate_draft_observations, read_capture_lifecycle_observation, read_contract,
    read_observations, resolve_exact_main, validate_capture_lifecycle_observation,
    validate_contract, validate_exact_main, validate_observations, validate_semantic_report,
    write_new_observations,
};

fn main() -> ExitCode {
    match run() {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => {
            eprintln!("performance-contract: {error}");
            ExitCode::FAILURE
        }
    }
}

fn run() -> Result<(), Box<dyn std::error::Error>> {
    let mut arguments = env::args_os().skip(1);
    let command = arguments
        .next()
        .and_then(|value| value.into_string().ok())
        .ok_or(
            "usage: performance-contract COMMAND CONTRACT REPO [SEMANTIC_REPORT] [OBSERVATIONS]",
        )?;
    let contract_path = path_argument(&mut arguments, "CONTRACT")?;
    let repo = path_argument(&mut arguments, "REPO")?;
    let contract = read_contract(&contract_path)?;
    validate_contract(&contract)?;
    let observed = resolve_exact_main(&repo)?;
    validate_exact_main(&contract, &observed)?;

    match command.as_str() {
        "validate-contract" => {
            require_end(arguments)?;
            println!(
                "contract={} main={} rows={} supported={} unsupported={} models={}",
                contract.contract_id,
                contract.canonical.commit,
                contract.semantic.denominator_rows,
                contract.semantic.supported_rows,
                contract.semantic.unsupported_rows,
                contract.models.len()
            );
        }
        "validate-semantic" => {
            let semantic_path = path_argument(&mut arguments, "SEMANTIC_REPORT")?;
            require_end(arguments)?;
            let semantic_bytes = fs::read(&semantic_path)?;
            let universe = validate_semantic_report(&contract, &semantic_bytes)?;
            println!(
                "contract={} semantic={} rows={} status=valid",
                contract.contract_id,
                contract.semantic.receipts_sha256,
                universe.len()
            );
        }
        "validate-observations" => {
            let semantic_path = path_argument(&mut arguments, "SEMANTIC_REPORT")?;
            let observations_path = path_argument(&mut arguments, "OBSERVATIONS")?;
            require_end(arguments)?;
            let semantic_bytes = fs::read(&semantic_path)?;
            let universe = validate_semantic_report(&contract, &semantic_bytes)?;
            let observations = read_observations(&observations_path)?;
            validate_observations(&contract, &universe, &observations)?;
            println!(
                "contract={} semantic={} rows={} phase={:?} status=valid",
                contract.contract_id,
                contract.semantic.receipts_sha256,
                observations.rows.len(),
                observations.phase
            );
        }
        "generate-draft" => {
            let semantic_path = path_argument(&mut arguments, "SEMANTIC_REPORT")?;
            let output_path = path_argument(&mut arguments, "OUTPUT")?;
            require_end(arguments)?;
            let semantic_bytes = fs::read(&semantic_path)?;
            let universe = validate_semantic_report(&contract, &semantic_bytes)?;
            let observations = generate_draft_observations(&contract, &universe)?;
            write_new_observations(&output_path, &observations)?;
            println!(
                "contract={} semantic={} rows={} phase=draft output={}",
                contract.contract_id,
                contract.semantic.receipts_sha256,
                observations.rows.len(),
                output_path.display()
            );
        }
        "validate-capture-observation" => {
            let semantic_path = path_argument(&mut arguments, "SEMANTIC_REPORT")?;
            let observation_path = path_argument(&mut arguments, "RAW_OBSERVATION")?;
            require_end(arguments)?;
            let semantic_bytes = fs::read(&semantic_path)?;
            let universe = validate_semantic_report(&contract, &semantic_bytes)?;
            let observation = read_capture_lifecycle_observation(&observation_path)?;
            validate_capture_lifecycle_observation(&contract, &universe, &observation)?;
            println!(
                "contract={} job={} model={} boundary={} status=valid",
                contract.contract_id,
                observation.job_id,
                observation.model,
                observation.boundary.as_str()
            );
        }
        other => return Err(format!("unknown command {other:?}").into()),
    }
    Ok(())
}

fn path_argument(
    arguments: &mut impl Iterator<Item = std::ffi::OsString>,
    name: &str,
) -> Result<PathBuf, Box<dyn std::error::Error>> {
    arguments
        .next()
        .map(PathBuf::from)
        .ok_or_else(|| format!("missing {name}").into())
}

fn require_end(
    mut arguments: impl Iterator<Item = std::ffi::OsString>,
) -> Result<(), Box<dyn std::error::Error>> {
    if arguments.next().is_some() {
        return Err("unexpected extra argument".into());
    }
    Ok(())
}
