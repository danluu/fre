#![forbid(unsafe_code)]

use std::{alloc::System, sync::Mutex};

use fre::{
    AggregateBuilder, AggregateExecutionDetails, AggregateExecutionSource, AggregatePlanKind,
    AggregateRunLimits, OrderedLiteralAggregateReduceLimits, RustProfile,
};
use stats_alloc::{INSTRUMENTED_SYSTEM, Region, StatsAlloc};

#[global_allocator]
static GLOBAL: &StatsAlloc<System> = &INSTRUMENTED_SYSTEM;
static ALLOCATION_TEST_LOCK: Mutex<()> = Mutex::new(());

fn aggregate_builder(pattern: impl Into<String>) -> AggregateBuilder {
    AggregateBuilder::new(pattern).profile(RustProfile::rebar_1_12_4())
}

fn allocation_count<T>(operation: impl FnOnce() -> T) -> (T, usize, usize, usize) {
    let region = Region::new(GLOBAL);
    let value = operation();
    let change = region.change();
    (
        value,
        change.allocations,
        change.reallocations,
        change.deallocations,
    )
}

#[test]
fn direct_terminal_receipts_preserve_existing_error_allocation_counts() {
    let _serial = ALLOCATION_TEST_LOCK.lock().unwrap();
    let exact = aggregate_builder("needle")
        .unicode(false)
        .build_count()
        .expect("exact build");
    assert_eq!(exact.build_report().plan, AggregatePlanKind::ExactLiteral);
    let mut exact_limits = AggregateRunLimits::default();
    exact_limits.exact_literal.max_linear_terms = 0;
    let (exact_error, allocations, reallocations, deallocations) =
        allocation_count(|| exact.count(b"needleneedle", exact_limits).unwrap_err());
    assert_eq!(allocations, 1, "only the pre-existing boxed identity");
    assert_eq!(reallocations, 0);
    assert_eq!(deallocations, 0);
    assert!(exact_error.has_closed_direct_attempt());

    let guarded = aggregate_builder(r"\b(?:as|break|Self|ab|ba)\b")
        .unicode(false)
        .build_count()
        .expect("guarded build");
    assert_eq!(
        guarded.build_report().plan,
        AggregatePlanKind::GuardedAsciiWordDictionary
    );
    let haystack = b"as break other Self ab ba";
    let baseline = guarded
        .count(haystack, AggregateRunLimits::default())
        .expect("guarded baseline");
    let AggregateExecutionDetails::GuardedAsciiWord(accounting) = baseline.report().details()
    else {
        panic!("guarded accounting");
    };
    let guarded_limits = AggregateRunLimits {
        finite_literal: OrderedLiteralAggregateReduceLimits {
            max_transitions: accounting.upper_bounds.haystack_bytes - 1,
            ..OrderedLiteralAggregateReduceLimits::default()
        },
        ..AggregateRunLimits::default()
    };
    drop(baseline);

    let (guarded_error, allocations, reallocations, deallocations) =
        allocation_count(|| guarded.count(haystack, guarded_limits).unwrap_err());
    assert_eq!(
        allocations, 2,
        "the pre-existing identity and public guarded-source boxes"
    );
    assert_eq!(reallocations, 0);
    assert_eq!(deallocations, 0);
    assert!(guarded_error.has_closed_direct_attempt());
    let receipt = guarded_error.direct_receipt().expect("guarded receipt");
    assert!(receipt.authenticates_source(&guarded_error.source));
    assert!(matches!(
        guarded_error.source,
        AggregateExecutionSource::GuardedAsciiWord(_)
    ));

    let fixed_predicate = aggregate_builder("Sherlock Holmes")
        .unicode(false)
        .case_insensitive(true)
        .build_count()
        .expect("fixed-predicate build");
    assert_eq!(
        fixed_predicate.build_report().plan,
        AggregatePlanKind::FixedPredicateWord64
    );
    let fixed_baseline = fixed_predicate
        .count(b"xxSherLock Holmesyy", AggregateRunLimits::default())
        .expect("fixed-predicate baseline");
    let AggregateExecutionDetails::FixedPredicateWord64(accounting) =
        fixed_baseline.report().details()
    else {
        panic!("fixed-predicate accounting");
    };
    let fixed_limits = AggregateRunLimits {
        finite_literal: OrderedLiteralAggregateReduceLimits {
            max_transitions: accounting.upper_bounds.transitions - 1,
            ..OrderedLiteralAggregateReduceLimits::default()
        },
        ..AggregateRunLimits::default()
    };
    drop(fixed_baseline);

    let (fixed_error, allocations, reallocations, deallocations) = allocation_count(|| {
        fixed_predicate
            .count(b"xxSherLock Holmesyy", fixed_limits)
            .unwrap_err()
    });
    assert_eq!(allocations, 1, "only the pre-existing boxed identity");
    assert_eq!(reallocations, 0);
    assert_eq!(deallocations, 0);
    assert!(fixed_error.has_closed_direct_attempt());
}

#[test]
fn direct_success_reports_remain_allocation_free() {
    let _serial = ALLOCATION_TEST_LOCK.lock().unwrap();
    let exact = aggregate_builder("needle")
        .unicode(false)
        .build_count()
        .expect("exact build");
    let (exact_result, allocations, reallocations, deallocations) = allocation_count(|| {
        exact
            .count(b"needleneedle", AggregateRunLimits::default())
            .unwrap()
    });
    assert_eq!((allocations, reallocations, deallocations), (0, 0, 0));
    assert!(exact_result.report().has_closed_direct_attempt());

    let guarded = aggregate_builder(r"\b(?:as|break|Self|ab|ba)\b")
        .unicode(false)
        .build_count()
        .expect("guarded build");
    let (guarded_result, allocations, reallocations, deallocations) = allocation_count(|| {
        guarded
            .count(b"as break other Self ab ba", AggregateRunLimits::default())
            .unwrap()
    });
    assert_eq!((allocations, reallocations, deallocations), (0, 0, 0));
    assert!(guarded_result.report().has_closed_direct_attempt());

    let fixed_predicate = aggregate_builder("Sherlock Holmes")
        .unicode(false)
        .case_insensitive(true)
        .build_count()
        .expect("fixed-predicate build");
    let (fixed_result, allocations, reallocations, deallocations) = allocation_count(|| {
        fixed_predicate
            .count(b"xxSherLock Holmesyy", AggregateRunLimits::default())
            .unwrap()
    });
    assert_eq!((allocations, reallocations, deallocations), (0, 0, 0));
    assert!(fixed_result.report().has_closed_direct_attempt());
}
