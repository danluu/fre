//! Structural scaling receipt for the exact-literal whole-operation plan.

use std::process::ExitCode;

use fre_kernels::{
    LiteralAggregateBuildLimits, LiteralAggregatePlan, LiteralAggregateReduceLimits,
};

fn main() -> ExitCode {
    match run() {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => {
            eprintln!("{error}");
            ExitCode::FAILURE
        }
    }
}

fn run() -> Result<(), String> {
    println!(
        "case\thaystack_bytes\tneedle_bytes\tlinear_terms\tevents_upper\tcount_upper\tspan_upper\tsteps_upper\tactual_events\tnext_calls\tempty_formulas\tactual_matched_bytes"
    );
    for size in [0_usize, 1, 8, 1_024, 2_048, 65_536, 1_048_576] {
        emit("sparse", b"xyz", &vec![b'a'; size])?;
        emit("dense", b"a", &vec![b'a'; size])?;
        emit("empty", b"", &vec![0xFF; size])?;
    }
    Ok(())
}

fn emit(case: &str, needle: &[u8], haystack: &[u8]) -> Result<(), String> {
    let plan = LiteralAggregatePlan::build(needle, LiteralAggregateBuildLimits::unlimited())
        .map_err(|error| error.to_string())?;
    let result = plan
        .count(haystack, LiteralAggregateReduceLimits::unlimited())
        .map_err(|error| error.to_string())?;
    let upper = result.accounting.upper_bounds;
    let actual = result.accounting.actual;
    println!(
        "{case}\t{}\t{}\t{}\t{}\t{}\t{}\t{}\t{}\t{}\t{}\t{}",
        upper.haystack_bytes,
        upper.needle_bytes,
        upper.linear_terms,
        upper.match_events,
        upper.count,
        upper.span_sum,
        upper.reducer_steps,
        actual.match_events,
        actual.iterator_next_calls,
        actual.empty_formula_evaluations,
        actual.matched_bytes,
    );
    Ok(())
}
