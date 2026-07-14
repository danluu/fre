use fre_iterator_lab::{Ast, CompileLimits, CompiledRegex, Greed, GuardedRegex};

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

#[test]
fn progress_product_has_linear_input_and_pattern_scaling() {
    let p32 = CompiledRegex::new(&wide(32), limits()).expect("p32");
    let p64 = CompiledRegex::new(&wide(64), limits()).expect("p64");
    let n64 = vec![b'a'; 64];
    let n128 = vec![b'a'; 128];
    let base = p32.find_all_full_dp(&n64).expect("base");
    let input = p32.find_all_full_dp(&n128).expect("input");
    let pattern = p64.find_all_full_dp(&n64).expect("pattern");
    let joint = p64.find_all_full_dp(&n128).expect("joint");
    assert_tenths_ratio(
        input.accounting.state_evaluations,
        base.accounting.state_evaluations,
        19,
        21,
    );
    assert_tenths_ratio(
        pattern.accounting.state_evaluations,
        base.accounting.state_evaluations,
        19,
        22,
    );
    assert_tenths_ratio(
        joint.accounting.state_evaluations,
        base.accounting.state_evaluations,
        38,
        44,
    );

    let base_log = p32.find_all_decision_log(&n64).expect("base log");
    let joint_log = p64.find_all_decision_log(&n128).expect("joint log");
    assert_tenths_ratio(
        joint_log.accounting.state_evaluations,
        base_log.accounting.state_evaluations,
        38,
        44,
    );
    let base_sequential = p32
        .find_all_sequential_row_log(&n64)
        .expect("base sequential");
    let joint_sequential = p64
        .find_all_sequential_row_log(&n128)
        .expect("joint sequential");
    assert_tenths_ratio(
        joint_sequential.accounting.state_evaluations,
        base_sequential.accounting.state_evaluations,
        38,
        44,
    );
    assert_eq!(
        joint_sequential.accounting.sequential_log_write_bytes,
        joint_sequential.accounting.sequential_log_bytes
    );
    assert!(
        joint_sequential.accounting.sequential_log_read_bytes
            <= joint_sequential.accounting.sequential_log_bytes
    );
}

#[test]
fn guarded_strategy_exposes_quadratic_one_guard_admission_growth() {
    let guarded = GuardedRegex::new(&witness(), limits()).expect("guarded");
    assert_eq!(guarded.guard_count(), 1);
    let small = guarded.find_all_guarded_dp(&[b'a'; 64]).expect("small");
    let large = guarded.find_all_guarded_dp(&[b'a'; 128]).expect("large");
    assert_eq!(small.matches.len(), 64);
    assert_eq!(large.matches.len(), 128);
    assert_tenths_ratio(
        large.accounting.guarded_configurations,
        small.accounting.guarded_configurations,
        38,
        42,
    );
    assert!(large.accounting.guarded_peak_frames < large.accounting.guarded_configurations);
}

fn assert_tenths_ratio(large: usize, small: usize, low: usize, high: usize) {
    let scaled = large.checked_mul(10).expect("test scale");
    let lower = small.checked_mul(low).expect("test lower");
    let upper = small.checked_mul(high).expect("test upper");
    assert!(
        (lower..=upper).contains(&scaled),
        "ratio {large}/{small} outside {low}/10..={high}/10"
    );
}
