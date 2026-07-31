use std::{env, error::Error, io};

use fre_jit_aarch64::SearchBackendPolicy;
use fre_search_v26_synthetic_runner::{
    EXPECTED_LITERAL_COUNT, MAX_WIDTH, MIN_WIDTH, SYNTHETIC_DOMAIN, generate_population, hex,
    native_correctness, report_only_emission_timing, static_parity,
};
use serde::Serialize;

#[derive(Serialize)]
struct PopulationSummary<'a> {
    schema: &'static str,
    domain_ascii: &'static str,
    domain_hex: String,
    minimum_width: u16,
    maximum_width: u16,
    output_kinds: [&'static str; 3],
    literal_count: usize,
    rejected_candidates: u64,
    population_sha256: String,
    admission: &'static str,
    timing: &'static str,
    literals: Option<&'a [fre_search_v26_synthetic_runner::SyntheticLiteral]>,
}

fn main() -> Result<(), Box<dyn Error>> {
    let mut arguments = env::args().skip(1);
    let command = arguments.next().unwrap_or_else(|| "summary".to_owned());
    if arguments.next().is_some() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "usage: fre-search-v26-synthetic-runner [summary|population|static|correctness|emission-timing]",
        )
        .into());
    }
    let population = generate_population()?;
    if command == "static" {
        let report = static_parity(&population, SearchBackendPolicy::AsimdV26)?;
        serde_json::to_writer(io::stdout().lock(), &report)?;
        println!();
        return Ok(());
    }
    if command == "correctness" {
        let report = native_correctness(&population, SearchBackendPolicy::AsimdV26)?;
        serde_json::to_writer(io::stdout().lock(), &report)?;
        println!();
        return Ok(());
    }
    if command == "emission-timing" {
        let report = report_only_emission_timing(&population)?;
        serde_json::to_writer(io::stdout().lock(), &report)?;
        println!();
        return Ok(());
    }
    let literals = match command.as_str() {
        "summary" => None,
        "population" => Some(population.literals()),
        _ => {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "command must be summary, population, static, correctness, or emission-timing",
            )
            .into());
        }
    };
    let summary = PopulationSummary {
        schema: "fre.aot.search-v26-fresh-synthetic-population.v1",
        domain_ascii: std::str::from_utf8(SYNTHETIC_DOMAIN)?,
        domain_hex: hex(SYNTHETIC_DOMAIN),
        minimum_width: MIN_WIDTH,
        maximum_width: MAX_WIDTH,
        output_kinds: ["exists", "span", "selected_end"],
        literal_count: EXPECTED_LITERAL_COUNT,
        rejected_candidates: population.rejected_candidates(),
        population_sha256: population.population_sha256_hex(),
        admission: "public-SearchBackendPolicy::AsimdV17-emission",
        timing: "not-run",
        literals,
    };
    serde_json::to_writer(io::stdout().lock(), &summary)?;
    println!();
    Ok(())
}
