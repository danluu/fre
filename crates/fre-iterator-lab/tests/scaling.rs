use fre_iterator_lab::{Ast, CompileLimits, CompiledRegex, Greed, RepeatAtom};

fn limits() -> CompileLimits {
    CompileLimits {
        max_boundaries: 4_096,
        max_table_cells: 4_000_000,
        max_work: 500_000_000,
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

fn wide_pattern(branches: usize) -> Ast {
    let mut alternatives = (1..branches)
        .map(|_| Ast::Concat(vec![Ast::Byte(b'b'), Ast::Byte(b'b')]))
        .collect::<Vec<_>>();
    alternatives.push(Ast::Byte(b'a'));
    Ast::Alt(alternatives)
}

#[test]
fn fixed_pattern_input_doubling_is_linear_but_repeated_oracle_is_quadratic() {
    let regex = CompiledRegex::new(&quadratic_witness(), limits()).expect("compile");
    let small_haystack = vec![b'a'; 64];
    let large_haystack = vec![b'a'; 128];
    let small_full = regex.find_all_full_dp(&small_haystack).expect("small full");
    let large_full = regex.find_all_full_dp(&large_haystack).expect("large full");
    let small_log = regex
        .find_all_decision_log(&small_haystack)
        .expect("small log");
    let large_log = regex
        .find_all_decision_log(&large_haystack)
        .expect("large log");
    let small_oracle = regex
        .find_all_oracle(&small_haystack)
        .expect("small oracle");
    let large_oracle = regex
        .find_all_oracle(&large_haystack)
        .expect("large oracle");

    assert_eq!(small_full.matches.len(), 64);
    assert_eq!(large_full.matches.len(), 128);
    assert_eq!(small_full.matches, small_log.matches);
    assert_eq!(large_full.matches, large_log.matches);
    assert_eq!(small_full.matches, small_oracle.matches);
    assert_eq!(large_full.matches, large_oracle.matches);

    assert_ratio_between(
        large_full.accounting.state_evaluations,
        small_full.accounting.state_evaluations,
        19,
        21,
    );
    assert_ratio_between(
        large_log.accounting.total_work,
        small_log.accounting.total_work,
        19,
        21,
    );
    assert_ratio_between(
        large_oracle.accounting.state_evaluations,
        small_oracle.accounting.state_evaluations,
        38,
        42,
    );
    assert_eq!(large_full.accounting.output_work, 128);
    assert_eq!(large_log.accounting.output_work, 128);
}

#[test]
fn fixed_input_pattern_doubling_and_joint_doubling_have_expected_slopes() {
    let p8 = CompiledRegex::new(&wide_pattern(8), limits()).expect("p8");
    let p16 = CompiledRegex::new(&wide_pattern(16), limits()).expect("p16");
    let n64 = vec![b'a'; 64];
    let n128 = vec![b'a'; 128];

    let fixed_small = p8.find_all_full_dp(&n64).expect("p8 n64");
    let fixed_large = p16.find_all_full_dp(&n64).expect("p16 n64");
    let joint_large = p16.find_all_full_dp(&n128).expect("p16 n128");
    assert_ratio_between(
        fixed_large.accounting.state_evaluations,
        fixed_small.accounting.state_evaluations,
        19,
        22,
    );
    assert_ratio_between(
        joint_large.accounting.state_evaluations,
        fixed_small.accounting.state_evaluations,
        38,
        44,
    );

    let log_small = p8.find_all_decision_log(&n64).expect("log p8 n64");
    let log_fixed = p16.find_all_decision_log(&n64).expect("log p16 n64");
    let log_joint = p16.find_all_decision_log(&n128).expect("log p16 n128");
    assert_ratio_between(
        log_fixed.accounting.state_evaluations,
        log_small.accounting.state_evaluations,
        19,
        22,
    );
    assert_ratio_between(
        log_joint.accounting.state_evaluations,
        log_small.accounting.state_evaluations,
        38,
        44,
    );

    assert!(
        fixed_small.accounting.random_access_peak_bytes
            > log_small.accounting.random_access_peak_bytes
    );
    assert!(log_small.accounting.sequential_log_bytes > 0);
    assert!(log_small.accounting.resident_log_bytes >= log_small.accounting.sequential_log_bytes);
}

fn assert_ratio_between(large: usize, small: usize, lower_tenths: usize, upper_tenths: usize) {
    let scaled_large = large.checked_mul(10).expect("small test counter");
    let lower = small.checked_mul(lower_tenths).expect("small lower bound");
    let upper = small.checked_mul(upper_tenths).expect("small upper bound");
    assert!(
        (lower..=upper).contains(&scaled_large),
        "ratio {large}/{small} is outside {lower_tenths}/10..={upper_tenths}/10"
    );
}
