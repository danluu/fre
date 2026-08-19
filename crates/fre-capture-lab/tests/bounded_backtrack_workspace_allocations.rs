#![forbid(unsafe_code)]
#![allow(
    clippy::arithmetic_side_effects,
    reason = "small exact capacity and one-below fixtures are independently bounded"
)]

use std::{alloc::System, mem::size_of};

use fre_capture_lab::{
    Ast, BoundedBacktrackWorkspace, BuildLimits, HistoryRegex, ResourceKind, SearchConfig,
    SearchError, SearchLimits, Window,
};
use stats_alloc::{INSTRUMENTED_SYSTEM, Region, Stats, StatsAlloc};

#[global_allocator]
static GLOBAL: &StatsAlloc<System> = &INSTRUMENTED_SYSTEM;

fn census<T>(operation: impl FnOnce() -> T) -> (T, Stats) {
    let region = Region::new(GLOBAL);
    let value = operation();
    (value, region.change())
}

#[test]
fn bounded_workspace_accounts_for_construction_and_reuses_search_scratch() {
    let regex = HistoryRegex::compile(&Ast::Byte(b'a').capture(1), BuildLimits::default())
        .expect("capture program");
    let max_search_bytes = 96;
    let limits = SearchLimits::default();
    let usage = regex
        .bounded_backtrack_workspace_usage(max_search_bytes, limits)
        .expect("workspace usage")
        .expect("compact bounded program");

    let (workspace, construction) = census(|| {
        regex
            .prepare_bounded_backtrack_workspace(max_search_bytes, limits)
            .expect("workspace preparation")
            .expect("compact bounded program")
    });
    assert_eq!(construction.allocations, 3);
    assert_eq!(construction.reallocations, 0);
    assert_eq!(construction.deallocations, 0);
    assert_eq!(construction.bytes_reallocated, 0);
    assert_eq!(
        construction.bytes_allocated,
        usage.persistent_bytes - size_of::<BoundedBacktrackWorkspace>()
    );
    let mut workspace = workspace;

    let absent = [b'x'; 96];
    let ((), absent_stats) = census(|| {
        for _ in 0..8 {
            let outcome = regex
                .captures_from_with_bounded_backtrack_workspace(
                    &mut workspace,
                    &absent,
                    Window::all(&absent),
                    0,
                    SearchConfig::LEFTMOST,
                    limits,
                )
                .expect("reused no-match search");
            assert!(outcome.captures.is_none());
        }
    });
    assert_eq!(absent_stats, Stats::default());

    let mut present = [b'x'; 96];
    present[80] = b'a';
    let ((), present_stats) = census(|| {
        for _ in 0..8 {
            let outcome = regex
                .captures_from_with_bounded_backtrack_workspace(
                    &mut workspace,
                    &present,
                    Window::all(&present),
                    0,
                    SearchConfig::LEFTMOST,
                    limits,
                )
                .expect("reused matching search");
            assert!(outcome.captures.is_some());
        }
    });
    assert_eq!(present_stats.allocations, 8);
    assert_eq!(present_stats.deallocations, 8);
    assert_eq!(present_stats.reallocations, 0);
    assert_eq!(present_stats.bytes_reallocated, 0);

    let prospective = regex
        .bounded_backtrack_prospective(
            Window {
                start: 0,
                end: max_search_bytes,
            },
            0,
            SearchConfig::LEFTMOST,
        )
        .expect("valid prospective")
        .expect("bounded route");
    let one_below = SearchLimits {
        max_state_visits: prospective.state_visits - 1,
        ..limits
    };
    let (refused, refusal_stats) =
        census(|| regex.prepare_bounded_backtrack_workspace(max_search_bytes, one_below));
    assert!(matches!(
        refused,
        Err(SearchError::Resource {
            kind: ResourceKind::StateVisits,
            ..
        })
    ));
    assert_eq!(refusal_stats, Stats::default());
}
