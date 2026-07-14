use fre_iterator_lab::{Ast, CompileLimits, CompiledRegex, Greed, RepeatAtom, RunReport};

fn main() {
    println!(
        "candidate,pattern_scale,input_len,states,matches,work,state_evals,root_probes,replay_steps,random_bytes,logical_log_bytes,resident_log_bytes,output_work,output_bytes,elapsed_ns"
    );
    for pattern_scale in [8, 16, 32] {
        let ast = wide_witness(pattern_scale);
        let regex = CompiledRegex::new(&ast, limits()).expect("compile");
        for input_len in [64, 128, 256] {
            let haystack = vec![b'a'; input_len];
            print_report(
                "full_dp",
                pattern_scale,
                input_len,
                regex.find_all_full_dp(&haystack).expect("full DP"),
            );
            print_report(
                "decision_log",
                pattern_scale,
                input_len,
                regex
                    .find_all_decision_log(&haystack)
                    .expect("decision log"),
            );
        }
    }
    let oracle_regex = CompiledRegex::new(&quadratic_witness(), limits()).expect("oracle compile");
    for input_len in [64, 128, 256] {
        let haystack = vec![b'a'; input_len];
        print_report(
            "repeated_oracle",
            1,
            input_len,
            oracle_regex.find_all_oracle(&haystack).expect("oracle"),
        );
    }
}

fn limits() -> CompileLimits {
    CompileLimits {
        max_boundaries: 4_096,
        max_table_cells: 8_000_000,
        max_work: 2_000_000_000,
        ..CompileLimits::default()
    }
}

fn quadratic_witness() -> Ast {
    Ast::Alt(vec![
        Ast::Concat(vec![
            Ast::Repeat {
                body: vec![RepeatAtom::AnyByte],
                greed: Greed::Greedy,
            },
            Ast::Byte(b'b'),
        ]),
        Ast::Byte(b'a'),
    ])
}

fn wide_witness(branches: usize) -> Ast {
    let mut alternatives = (1..branches)
        .map(|_| Ast::Concat(vec![Ast::Byte(b'b'), Ast::Byte(b'b')]))
        .collect::<Vec<_>>();
    alternatives.push(quadratic_witness());
    Ast::Alt(alternatives)
}

fn print_report(candidate: &str, scale: usize, input_len: usize, report: RunReport) {
    let accounting = report.accounting;
    println!(
        "{candidate},{scale},{input_len},{},{},{},{},{},{},{},{},{},{},{},{}",
        accounting.program_states,
        report.matches.len(),
        accounting.total_work,
        accounting.state_evaluations,
        accounting.root_probes,
        accounting.replay_steps,
        accounting.random_access_peak_bytes,
        accounting.sequential_log_bytes,
        accounting.resident_log_bytes,
        accounting.output_work,
        accounting.output_bytes,
        accounting.elapsed.as_nanos(),
    );
}
