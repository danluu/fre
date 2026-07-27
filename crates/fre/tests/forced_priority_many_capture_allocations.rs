#![forbid(unsafe_code)]

use std::{alloc::System, sync::Mutex};

use fre::{PriorityAggregateManyBuilder, PriorityAggregateManyCaptureRunLimits};
use fre_automata::{ForcedExecution, PriorityTarget, TaggedManyExecutionClass};
use stats_alloc::{INSTRUMENTED_SYSTEM, Region, Stats, StatsAlloc};

#[global_allocator]
static GLOBAL: &StatsAlloc<System> = &INSTRUMENTED_SYSTEM;
static ALLOCATOR_CENSUS_LOCK: Mutex<()> = Mutex::new(());

fn census<T>(operation: impl FnOnce() -> T) -> (T, Stats) {
    let region = Region::new(GLOBAL);
    let value = operation();
    (value, region.change())
}

#[test]
fn reusable_forced_capture_session_has_no_steady_allocator_activity() {
    let _census_lock = ALLOCATOR_CENSUS_LOCK.lock().expect("census lock");
    let patterns = vec![
        r"(?:a|(ab))c".to_owned(),
        r"(?:(d)|(e))f".to_owned(),
        r"(?P<g>g)".to_owned(),
    ];
    let regex = PriorityAggregateManyBuilder::new(&patterns)
        .unicode(false)
        .build_capture_count(ForcedExecution::Sparse, PriorityTarget::portable())
        .expect("capture artifact");
    let mut session = regex
        .prepare_capture_session(
            b"abcdfg".len(),
            PriorityAggregateManyCaptureRunLimits::default(),
        )
        .expect("capture session");

    // Warm the exact reset paths outside the census. The workspace was fully
    // reserved during preparation; this simply proves the same ownership is
    // reused on every later public operation.
    session.count_captures(b"abcdfg").expect("warmup");

    for haystack in [b"abcdfg".as_slice(), b"abcxfg".as_slice()] {
        let (result, stats) = census(|| session.count_captures(haystack).expect("steady run"));
        assert_eq!(stats, Stats::default());
        assert_eq!(0, result.capture_accounting().allocations);
        assert!(
            result.selector_receipt().is_some_and(|receipt| receipt
                .execution()
                .actual()
                .allocation_attempts
                == 0)
        );
        assert!(result.closes());
    }
}

#[test]
fn capture_session_setup_receipt_matches_the_allocator_census() {
    let _census_lock = ALLOCATOR_CENSUS_LOCK.lock().expect("census lock");
    let patterns = vec![
        r"(?:a|(ab))c".to_owned(),
        r"(?:(d)|(e))f".to_owned(),
        r"(?P<g>g)".to_owned(),
    ];
    let regex = PriorityAggregateManyBuilder::new(&patterns)
        .unicode(false)
        .build_capture_count(ForcedExecution::Sparse, PriorityTarget::portable())
        .expect("capture artifact");

    // Keep the completed workspace alive beyond the measured region, so the
    // census is exactly the setup owner's allocations, not its later drops.
    let (session, stats) = census(|| {
        regex
            .prepare_capture_session(
                b"abcdfg".len(),
                PriorityAggregateManyCaptureRunLimits::default(),
            )
            .expect("capture session")
    });
    let accounting = session.accounting();
    assert_eq!(stats.allocations, accounting.allocations);
    assert_eq!(stats.bytes_allocated, accounting.persistent_bytes);
    assert_eq!(0, stats.reallocations);
    assert_eq!(0, stats.deallocations);
    assert!(accounting.closes(PriorityAggregateManyCaptureRunLimits::default().session));
}

#[test]
fn shared_frontier_capture_session_setup_matches_the_allocator_census() {
    let _census_lock = ALLOCATOR_CENSUS_LOCK.lock().expect("census lock");
    let patterns = vec![r"([a-z])".to_owned(); 2];
    let regex = PriorityAggregateManyBuilder::new(&patterns)
        .unicode(false)
        .build_capture_count(ForcedExecution::Sparse, PriorityTarget::portable())
        .expect("shared-frontier capture artifact");
    let (mut session, stats) = census(|| {
        regex
            .prepare_capture_session(
                b"ababab".len(),
                PriorityAggregateManyCaptureRunLimits::default(),
            )
            .expect("shared-frontier capture session")
    });
    let accounting = session.accounting();
    assert_eq!(stats.allocations, accounting.allocations);
    assert_eq!(stats.bytes_allocated, accounting.persistent_bytes);
    assert_eq!(0, stats.reallocations);
    assert_eq!(0, stats.deallocations);
    let result = session.count_captures(b"ababab").expect("shared run");
    assert!(matches!(
        result
            .selector_receipt()
            .expect("shared selector receipt")
            .execution()
            .tagged_stats()
            .execution_class(),
        TaggedManyExecutionClass::SharedFrontierUniformRangeChain { .. }
    ));
    assert!(result.closes());
}
