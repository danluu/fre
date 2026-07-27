#![forbid(unsafe_code)]

use std::alloc::System;

use fre::operation_session::{grep, hot, multi_capture, search};
use fre::{
    OperationSession, OperationSessionAdmission, OperationSessionConstructionLimits,
    OperationSessionLeaf, OperationSessionResetLimits,
};
use stats_alloc::{INSTRUMENTED_SYSTEM, Region, Stats, StatsAlloc};

#[global_allocator]
static GLOBAL: &StatsAlloc<System> = &INSTRUMENTED_SYSTEM;

#[test]
fn fixed_layout_repeated_resets_have_zero_steady_allocation() {
    let admission = OperationSessionAdmission {
        search: search::SlotAdmission {
            frontier_cells: 7,
            next_frontier_cells: 7,
            generation_cells: 11,
            candidate_cells: 5,
            cache_cells: 3,
            history_cells: 2,
        },
        hot: hot::SlotAdmission {
            state_cells: 9,
            generation_cells: 13,
            candidate_cells: 5,
            cache_cells: 3,
            history_cells: 2,
        },
        multi_capture: multi_capture::SlotAdmission {
            frontier_cells: 7,
            next_frontier_cells: 7,
            generation_cells: 17,
            tagged_candidate_cells: 5,
            tagged_cache_cells: 3,
            history_cells: 2,
            participation_cells: 4,
        },
        grep: grep::SlotAdmission {
            line_state_cells: 9,
            generation_cells: 19,
            candidate_cells: 5,
            cache_cells: 3,
            history_cells: 2,
        },
    };
    let prospective = OperationSession::prospective(&admission).unwrap();
    let limits = OperationSessionConstructionLimits::exact(&prospective);
    let mut session = OperationSession::try_new(admission, limits).unwrap();
    let construction_before = session.construction_receipt().clone();
    let layouts_before = construction_before.leaves.map(|leaf| leaf.layout_id);
    let reset_limits = OperationSessionResetLimits {
        max_work: 1,
        max_clear_cells: 0,
        max_clear_bytes: 0,
    };

    let region = Region::new(GLOBAL);
    for leaf in OperationSessionLeaf::ORDERED {
        for _ in 0..32 {
            let before = session.counters(leaf);
            let receipt = session.reset_forced(leaf, 0, reset_limits).unwrap();
            assert!(receipt.closes());
            assert_eq!(receipt.actual.counters_before, before);
            assert_eq!(receipt.actual.counters_after.generation, before.generation);
            assert_eq!(
                receipt.actual.counters_after.reset_invocations,
                before.reset_invocations.checked_add(1).unwrap()
            );
            assert_eq!(receipt.actual.counters_after.rollovers, before.rollovers);
            assert_eq!(receipt.actual.counters_after.clears, before.clears);
            assert_eq!(
                receipt.actual.counters_after.clear_cells,
                before.clear_cells
            );
            assert_eq!(
                receipt.actual.counters_after.clear_bytes,
                before.clear_bytes
            );
        }
    }
    let change = region.change();

    assert_eq!(change, Stats::default());
    assert_eq!(session.construction_receipt(), &construction_before);
    assert_eq!(
        session
            .construction_receipt()
            .leaves
            .map(|leaf| leaf.layout_id),
        layouts_before
    );
}
