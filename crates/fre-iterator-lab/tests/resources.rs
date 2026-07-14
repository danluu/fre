use fre_iterator_lab::{
    Ast, CompileLimits, CompiledRegex, Error, Greed, GuardedRegex, ResourceKind,
};

#[test]
fn logical_and_resident_log_limits_are_distinct_and_preflighted() {
    let regex = CompiledRegex::new(&Ast::Empty, CompileLimits::default()).expect("compile");
    let logical = CompileLimits {
        max_log_bytes: 0,
        ..CompileLimits::default()
    };
    let logical_regex = CompiledRegex::new(&Ast::Empty, logical).expect("compile logical");
    assert!(matches!(
        logical_regex.find_all_decision_log(b""),
        Err(Error::ResourceLimit {
            kind: ResourceKind::LogBytes,
            ..
        })
    ));

    let resident = CompileLimits {
        max_log_bytes: 1,
        max_resident_log_bytes: 1,
        ..CompileLimits::default()
    };
    let resident_regex = CompiledRegex::new(&Ast::Empty, resident).expect("compile resident");
    assert!(matches!(
        resident_regex.find_all_decision_log(b""),
        Err(Error::ResourceLimit {
            kind: ResourceKind::ResidentLogBytes,
            ..
        })
    ));
    assert!(regex.find_all_decision_log(b"").is_ok());
}

#[test]
fn guarded_state_space_and_guard_count_are_preflighted() {
    let star = Ast::Repetition {
        child: Box::new(Ast::Byte(b'a')),
        min: 0,
        max: None,
        greed: Greed::Greedy,
    };
    let no_guards = CompileLimits {
        max_guard_count: 0,
        ..CompileLimits::default()
    };
    assert!(matches!(
        GuardedRegex::new(&star, no_guards),
        Err(Error::ResourceLimit {
            kind: ResourceKind::GuardCount,
            ..
        })
    ));

    let tiny_state_space = CompileLimits {
        max_guarded_configurations: 1,
        ..CompileLimits::default()
    };
    let guarded = GuardedRegex::new(&star, tiny_state_space).expect("guarded compile");
    assert!(matches!(
        guarded.find_all_guarded_dp(b"a"),
        Err(Error::ResourceLimit {
            kind: ResourceKind::GuardedConfigurations,
            ..
        })
    ));
}

#[test]
fn general_repetition_ranges_and_transformed_program_size_are_checked() {
    let invalid = Ast::Repetition {
        child: Box::new(Ast::Byte(b'a')),
        min: 2,
        max: Some(1),
        greed: Greed::Greedy,
    };
    assert_eq!(
        CompiledRegex::new(&invalid, CompileLimits::default()).expect_err("invalid range"),
        Error::InvalidRepeatRange
    );
    assert_eq!(
        GuardedRegex::new(&invalid, CompileLimits::default()).expect_err("invalid guard range"),
        Error::InvalidRepeatRange
    );

    let oversized = Ast::Repetition {
        child: Box::new(Ast::Empty),
        min: 1_001,
        max: Some(1_001),
        greed: Greed::Greedy,
    };
    assert!(matches!(
        CompiledRegex::new(&oversized, CompileLimits::default()),
        Err(Error::ResourceLimit {
            kind: ResourceKind::RepeatBound,
            ..
        })
    ));

    let nested = Ast::Repetition {
        child: Box::new(Ast::Repetition {
            child: Box::new(Ast::Byte(b'a')),
            min: 0,
            max: None,
            greed: Greed::Greedy,
        }),
        min: 0,
        max: None,
        greed: Greed::Greedy,
    };
    let tiny_program = CompileLimits {
        max_program_states: 3,
        ..CompileLimits::default()
    };
    assert!(matches!(
        CompiledRegex::new(&nested, tiny_program),
        Err(Error::ResourceLimit {
            kind: ResourceKind::ProgramStates,
            ..
        })
    ));
}

#[test]
fn table_row_work_and_output_limits_fail_before_execution() {
    let tiny_table = CompileLimits {
        max_random_access_bytes: 1,
        ..CompileLimits::default()
    };
    let regex = CompiledRegex::new(&Ast::Byte(b'a'), tiny_table).expect("compile table");
    assert!(matches!(
        regex.find_all_full_dp(b"a"),
        Err(Error::ResourceLimit {
            kind: ResourceKind::RandomAccessBytes,
            ..
        })
    ));

    let tiny_work = CompileLimits {
        max_work: 1,
        ..CompileLimits::default()
    };
    let regex = CompiledRegex::new(&Ast::Byte(b'a'), tiny_work).expect("compile work");
    assert!(matches!(
        regex.find_all_decision_log(b"a"),
        Err(Error::ResourceLimit {
            kind: ResourceKind::Work,
            ..
        })
    ));

    let tiny_output = CompileLimits {
        max_output_bytes: 1,
        ..CompileLimits::default()
    };
    let regex = CompiledRegex::new(&Ast::Empty, tiny_output).expect("compile output");
    assert!(matches!(
        regex.find_all_full_dp(b""),
        Err(Error::ResourceLimit {
            kind: ResourceKind::OutputBytes,
            ..
        })
    ));
}
