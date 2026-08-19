use fre::{
    AggregateBuildError, AggregateBuildLimits, AggregateBuilder, AggregateOperation,
    AggregatePlanKind, AggregatePlanSelection,
};

#[test]
fn unbounded_languages_refuse_finite_extraction_before_allocation() {
    std::thread::Builder::new()
        .name("finite-unbounded-preflight".to_owned())
        .stack_size(8 * 1024 * 1024)
        .spawn(unbounded_languages_refuse_finite_extraction_before_allocation_body)
        .unwrap()
        .join()
        .unwrap();
}

fn unbounded_languages_refuse_finite_extraction_before_allocation_body() {
    let unbounded = AggregateBuilder::new("(?:ab|cd)+z")
        .unicode(false)
        .build_compile()
        .expect("unbounded language must retain complete continuation compilation");
    let report = unbounded.build_report();
    assert_eq!(report.plan, AggregatePlanKind::ContinuationProgram);
    // Two steps close the finite refusal; the remaining bounded work is the
    // independent compact-predicate probe that follows that refusal.
    assert_eq!(report.finite_planner_work, 8);

    let mut limits = AggregateBuildLimits::default();
    limits.max_finite_planner_work = 1;
    assert!(matches!(
        AggregateBuilder::new("(?:ab|cd)+z")
            .unicode(false)
            .limits(limits)
            .build_compile(),
        Err(AggregateBuildError::FinitePlannerWorkLimit {
            operation: AggregateOperation::Compile,
            selection: AggregatePlanSelection::Auto,
            needed: 2,
            limit: 1,
        })
    ));

    let bounded = AggregateBuilder::new("foo|bar")
        .unicode(false)
        .build_compile()
        .expect("bounded finite language remains eligible");
    assert_ne!(
        bounded.build_report().plan,
        AggregatePlanKind::ContinuationProgram
    );
    assert!(bounded.build_report().finite_planner_work > 8);

    let empty = AggregateBuilder::new("[a&&b]")
        .unicode(true)
        .build_compile()
        .expect("an empty language must retain the incumbent finite-planner path");
    assert!(empty.build_report().finite_planner_work > 2);
}
