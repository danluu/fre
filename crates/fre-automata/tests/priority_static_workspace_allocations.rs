#![forbid(unsafe_code)]

use std::alloc::System;

use fre_automata::{
    ActionCapabilities, Automaton, CompileLimits, DirectCount, DirectReduceLimits, EdgeKind,
    EmptyMatchProgress, ForcedExecution, MatchLengthProof, PatternAction, PatternOrdinal,
    PreparationLimits, PriorityAutomataFacts, PriorityStaticWorkspaceError,
    PriorityStaticWorkspaceLimits, PriorityTarget, RawPlan, StateRole,
};
use stats_alloc::{Region, Stats, StatsAlloc, INSTRUMENTED_SYSTEM};

#[global_allocator]
static GLOBAL: &StatsAlloc<System> = &INSTRUMENTED_SYSTEM;

fn literal() -> PriorityAutomataFacts {
    let automaton = Automaton::from_raw(
        RawPlan {
            start: 0,
            roles: vec![StateRole::Consume, StateRole::Accept],
            edge_offsets: vec![0, 1, 1],
            edge_targets: vec![1],
            edge_kinds: vec![EdgeKind::ByteRange],
            byte_starts: vec![b'a'],
            byte_ends: vec![b'a'],
        },
        CompileLimits::default(),
    )
    .unwrap();
    PriorityAutomataFacts::new(
        automaton,
        vec![
            None,
            Some(PatternAction::new(
                PatternOrdinal::new(0),
                ActionCapabilities::all(),
            )),
        ],
        MatchLengthProof::Exact(1),
        EmptyMatchProgress::Byte,
    )
}

fn zero_width_cycle() -> PriorityAutomataFacts {
    let automaton = Automaton::from_raw(
        RawPlan {
            start: 0,
            roles: vec![StateRole::Split, StateRole::Split, StateRole::Accept],
            edge_offsets: vec![0, 2, 3, 3],
            edge_targets: vec![1, 2, 0],
            edge_kinds: vec![EdgeKind::Epsilon; 3],
            byte_starts: vec![0; 3],
            byte_ends: vec![0; 3],
        },
        CompileLimits::default(),
    )
    .unwrap();
    PriorityAutomataFacts::new(
        automaton,
        vec![
            None,
            None,
            Some(PatternAction::new(
                PatternOrdinal::new(0),
                ActionCapabilities::all(),
            )),
        ],
        MatchLengthProof::Exact(0),
        EmptyMatchProgress::Byte,
    )
}

fn allocation_free_limits() -> DirectReduceLimits {
    DirectReduceLimits {
        max_allocation_attempts: 0,
        ..DirectReduceLimits::unlimited()
    }
}

#[test]
fn prepared_full_and_finite_priority_workspaces_allocate_nothing_per_run() {
    let (full_automaton, full) = literal()
        .prepare_forced_parts::<DirectCount>(
            ForcedExecution::FullDfa,
            PriorityTarget::portable(),
            PreparationLimits::unlimited(),
        )
        .unwrap();
    let mut full_workspace = full
        .prepare_static_workspace(&full_automaton, PriorityStaticWorkspaceLimits::unlimited())
        .unwrap()
        .unwrap();
    let full_region = Region::new(GLOBAL);
    let full_report = full
        .execute_forced_with_workspace(
            &full_automaton,
            b"zaaaz",
            &mut full_workspace,
            allocation_free_limits(),
        )
        .unwrap();
    let full_allocations = full_region.change();
    assert_eq!(full_allocations, Stats::default());
    assert_eq!(*full_report.output(), 3);
    assert_eq!(full_report.actual().allocation_attempts, 0);

    let (finite_automaton, finite) = literal()
        .prepare_forced_parts::<DirectCount>(
            ForcedExecution::FiniteHorizon,
            PriorityTarget::portable(),
            PreparationLimits::unlimited(),
        )
        .unwrap();
    let mut finite_workspace = finite
        .prepare_static_workspace(
            &finite_automaton,
            PriorityStaticWorkspaceLimits::unlimited(),
        )
        .unwrap()
        .unwrap();
    let wrong_finite_automaton = finite_automaton.clone();
    let mismatch_region = Region::new(GLOBAL);
    assert!(matches!(
        finite.prepare_static_workspace(
            &wrong_finite_automaton,
            PriorityStaticWorkspaceLimits::unlimited(),
        ),
        Err(PriorityStaticWorkspaceError::PreparedRouteAutomatonMismatch)
    ));
    let mismatch_allocations = mismatch_region.change();
    assert_eq!(mismatch_allocations, Stats::default());
    let finite_region = Region::new(GLOBAL);
    let finite_report = finite
        .execute_forced_with_workspace(
            &finite_automaton,
            b"zaaaz",
            &mut finite_workspace,
            allocation_free_limits(),
        )
        .unwrap();
    let finite_allocations = finite_region.change();
    assert_eq!(finite_allocations, Stats::default());
    assert_eq!(*finite_report.output(), 3);
    assert_eq!(finite_report.actual().allocation_attempts, 0);

    let cyclic = zero_width_cycle()
        .prepare_forced::<DirectCount>(
            ForcedExecution::FiniteHorizon,
            PriorityTarget::portable(),
            PreparationLimits::unlimited(),
        )
        .unwrap();
    let mut cyclic_workspace = cyclic
        .prepare_static_workspace(PriorityStaticWorkspaceLimits::unlimited())
        .unwrap()
        .unwrap();
    let cyclic_region = Region::new(GLOBAL);
    let cyclic_report = cyclic
        .execute_forced_with_workspace(b"zaaaz", &mut cyclic_workspace, allocation_free_limits())
        .unwrap();
    let cyclic_allocations = cyclic_region.change();
    assert_eq!(cyclic_allocations, Stats::default());
    assert_eq!(*cyclic_report.output(), 6);
    assert_eq!(cyclic_report.actual().allocation_attempts, 0);
}
