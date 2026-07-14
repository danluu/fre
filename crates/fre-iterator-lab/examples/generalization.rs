use fre_iterator_lab::{Ast, CompileLimits, CompiledRegex, Greed, GuardedRegex, RunReport};

fn main() {
    println!(
        "strategy,pattern_scale,input_len,states,guards,matches,work,state_evals,guarded_cells,random_bytes,log_bytes,log_written,log_read,elapsed_ns"
    );
    for pattern_scale in [32, 64] {
        let ast = wide(pattern_scale);
        let compiled = CompiledRegex::new(&ast, limits()).expect("progress-product compile");
        for input_len in [64, 128] {
            let haystack = vec![b'a'; input_len];
            print_report(
                "progress_full",
                pattern_scale,
                input_len,
                compiled.state_count(),
                0,
                compiled.find_all_full_dp(&haystack).expect("full DP"),
            );
            print_report(
                "progress_packed_log",
                pattern_scale,
                input_len,
                compiled.state_count(),
                0,
                compiled
                    .find_all_decision_log(&haystack)
                    .expect("packed log"),
            );
            print_report(
                "progress_sequential_rows",
                pattern_scale,
                input_len,
                compiled.state_count(),
                0,
                compiled
                    .find_all_sequential_row_log(&haystack)
                    .expect("sequential rows"),
            );
        }
    }

    let ast = witness();
    let guarded = GuardedRegex::new(&ast, limits()).expect("guarded compile");
    for input_len in [32, 64, 128] {
        let haystack = vec![b'a'; input_len];
        print_report(
            "guarded_dp",
            1,
            input_len,
            guarded.state_count(),
            guarded.guard_count(),
            guarded.find_all_guarded_dp(&haystack).expect("guarded DP"),
        );
    }
}

fn limits() -> CompileLimits {
    CompileLimits {
        max_boundaries: 1_024,
        max_table_cells: 8_000_000,
        max_guarded_configurations: 8_000_000,
        max_guarded_bytes: 256 * 1_024 * 1_024,
        max_work: 1_000_000_000,
        ..CompileLimits::default()
    }
}

fn repetition(child: Ast) -> Ast {
    Ast::Repetition {
        child: Box::new(child),
        min: 0,
        max: None,
        greed: Greed::Greedy,
    }
}

fn witness() -> Ast {
    Ast::Alt(vec![
        Ast::Concat(vec![repetition(Ast::AnyByte), Ast::Byte(b'b')]),
        Ast::Byte(b'a'),
    ])
}

fn wide(branches: usize) -> Ast {
    let mut alternatives = (1..branches)
        .map(|_| Ast::Concat(vec![Ast::Byte(b'b'), Ast::Byte(b'b')]))
        .collect::<Vec<_>>();
    alternatives.push(witness());
    Ast::Alt(alternatives)
}

fn print_report(
    strategy: &str,
    pattern_scale: usize,
    input_len: usize,
    states: usize,
    guards: usize,
    report: RunReport,
) {
    let accounting = report.accounting;
    println!(
        "{strategy},{pattern_scale},{input_len},{states},{guards},{},{},{},{},{},{},{},{},{}",
        report.matches.len(),
        accounting.total_work,
        accounting.state_evaluations,
        accounting.guarded_configurations,
        accounting.random_access_peak_bytes,
        accounting.sequential_log_bytes,
        accounting.sequential_log_write_bytes,
        accounting.sequential_log_read_bytes,
        accounting.elapsed.as_nanos(),
    );
}
