use std::{env, error::Error, io};

use fre_search_v26_synthetic_runner::{
    EXPECTED_LITERAL_COUNT, MAX_WIDTH, MIN_WIDTH, SYNTHETIC_DOMAIN, generate_population, hex,
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
            "usage: fre-search-v26-synthetic-runner [summary|population]",
        )
        .into());
    }
    let population = generate_population()?;
    let literals = match command.as_str() {
        "summary" => None,
        "population" => Some(population.literals()),
        _ => {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "command must be summary or population",
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
