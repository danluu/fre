#![forbid(unsafe_code)]

use std::alloc::System;

use fre::{
    AggregateBuildLimits, AggregateBuilder, AggregateConstructionActual,
    AggregateConstructionPrepublicationFallback, AggregateConstructionReceipt,
    AggregateConstructionStage, AggregateConstructionStageDisposition,
    AggregateConstructionTransition, AggregatePlanSelection, RustProfile,
};
use stats_alloc::{INSTRUMENTED_SYSTEM, Region, Stats, StatsAlloc};

#[global_allocator]
static GLOBAL: &StatsAlloc<System> = &INSTRUMENTED_SYSTEM;

fn builder(pattern: &str) -> AggregateBuilder {
    AggregateBuilder::new(pattern).profile(RustProfile::rebar_1_12_4())
}

fn allocation_census<T>(operation: impl FnOnce() -> T) -> (T, Stats) {
    let region = Region::new(GLOBAL);
    let value = operation();
    (value, region.change())
}

fn assert_controlled_allocation_ledger(receipt: &AggregateConstructionReceipt) {
    assert!(receipt.actual.is_well_formed());
    if let Some(prospective) = receipt.prospective {
        assert!(prospective.contains(receipt.actual));
    } else {
        assert_eq!(receipt.actual, AggregateConstructionActual::default());
    }
    let effect_allocations = receipt.ledger.iter().try_fold(0_usize, |total, entry| {
        total.checked_add(entry.effect.allocations)
    });
    let abandoned_allocations = receipt.ledger.iter().try_fold(0_usize, |total, entry| {
        total.checked_add(entry.abandonment.allocations)
    });
    assert_eq!(effect_allocations, Some(receipt.actual.allocations));
    assert_eq!(
        abandoned_allocations,
        Some(receipt.actual.abandoned_allocations)
    );
}

#[test]
#[allow(
    clippy::too_many_lines,
    reason = "one serialized allocator region audit prevents cross-test global-allocation interference"
)]
fn whole_construction_has_an_exact_controlled_allocation_census() {
    let success_builder = builder("needle").unicode(false);
    let (success, census) = allocation_census(|| success_builder.build_count_attempt().unwrap());
    let success_report = success.build_report();
    assert!(success_report.has_closed_construction_attempt());
    let success_receipt = success_report
        .construction_attempt_receipt()
        .expect("successful construction lost its receipt");
    assert_controlled_allocation_ledger(success_receipt);
    assert_eq!(success_receipt.actual.allocations, 4);
    assert_eq!(
        census,
        Stats {
            allocations: 25,
            deallocations: 21,
            reallocations: 4,
            // The composed continuation owner includes complete fixed inline
            // state-byte and ordered bounded-span slots. The latter moves the
            // owner to the next allocator size class, adding 56 bytes without
            // adding an allocation.
            bytes_allocated: 4_236,
            bytes_deallocated: 1_894,
            bytes_reallocated: 149,
        }
    );

    // The builder owns the source String before the allocator boundary. A
    // pre-P terminal moves that owner into a complete inline error/receipt:
    // packaging itself performs no allocation, reallocation, or deallocation.
    let pre_p_limits = AggregateBuildLimits {
        max_literal_planner_work: usize::MAX,
        ..AggregateBuildLimits::default()
    };
    let pre_p_builder = builder("needle").unicode(false).limits(pre_p_limits);
    let (pre_p, census) = allocation_census(|| pre_p_builder.build_count_attempt().unwrap_err());
    assert!(pre_p.closes());
    assert_controlled_allocation_ledger(pre_p.receipt());
    assert_eq!(
        pre_p.receipt().actual,
        AggregateConstructionActual::default()
    );
    assert_eq!(census, Stats::default());

    let post_p_limits = AggregateBuildLimits {
        max_literal_planner_work: 0,
        ..AggregateBuildLimits::default()
    };
    let post_p_builder = builder("needle")
        .unicode(false)
        .limits(post_p_limits)
        .plan_selection(AggregatePlanSelection::ForceExactLiteral);
    let (post_p, census) = allocation_census(|| post_p_builder.build_count_attempt().unwrap_err());
    assert!(post_p.closes());
    assert_controlled_allocation_ledger(post_p.receipt());
    assert_eq!(post_p.receipt().actual.allocations, 2);
    assert_eq!(
        census,
        Stats {
            allocations: 23,
            deallocations: 21,
            reallocations: 4,
            bytes_allocated: 2_182,
            bytes_deallocated: 1_894,
            bytes_reallocated: 149,
        }
    );
    // Every ordinary allocation beyond the two retained, charged owners is a
    // parser temporary that was deallocated. The terminal wrapper therefore
    // did not retain an unbudgeted allocation after the failure.
    assert_eq!(
        census
            .allocations
            .checked_sub(post_p.receipt().actual.allocations),
        Some(census.deallocations)
    );

    let fallback_limits = AggregateBuildLimits {
        max_fixed_absolute_planner_work: 1,
        ..AggregateBuildLimits::default()
    };
    let fallback_builder = builder(r"^a{2,5}$").unicode(false).limits(fallback_limits);
    let (fallback, census) = allocation_census(|| fallback_builder.build_count_attempt().unwrap());
    let fallback_receipt = fallback
        .build_report()
        .construction_attempt_receipt()
        .expect("fallback construction lost its receipt");
    assert_controlled_allocation_ledger(fallback_receipt);
    assert_eq!(fallback_receipt.actual.allocations, 20);
    assert!(fallback_receipt.actual.abandoned_work > 0);
    let fallback_entry = fallback_receipt
        .ledger
        .iter()
        .find(|entry| {
            entry.disposition == AggregateConstructionStageDisposition::SoftResourceRefused
        })
        .expect("fixed optional refusal lost its typed fallback");
    assert_eq!(
        (
            fallback_entry.stage,
            fallback_entry.fallback,
            fallback_entry.transition,
        ),
        (
            AggregateConstructionStage::FixedAbsolute,
            AggregateConstructionPrepublicationFallback::FixedAbsoluteOptionalInspectionResource,
            AggregateConstructionTransition::FixedAbsoluteToSparseFiniteRoot,
        )
    );
    assert_eq!(
        census,
        Stats {
            allocations: 47,
            deallocations: 39,
            reallocations: 5,
            // The same composed continuation owner reaches publication after
            // the optional fixed-route refusal.
            bytes_allocated: 7_434,
            bytes_deallocated: 4_297,
            bytes_reallocated: 912,
        }
    );

    // Moving the already packaged typed source and receipt back out performs
    // no new allocation. The two now-redundant retained owner allocations are
    // released while the public source and receipt move out inline.
    let ((post_p_source, post_p_receipt), unpack_census) =
        allocation_census(|| post_p.into_parts());
    assert_eq!(
        unpack_census,
        Stats {
            allocations: 0,
            deallocations: 2,
            reallocations: 0,
            bytes_allocated: 0,
            bytes_deallocated: 278,
            bytes_reallocated: 0,
        }
    );
    assert_eq!(post_p_receipt.actual.allocations, 2);

    // Keep every measured owner live until all allocator regions have closed.
    drop((success, pre_p, fallback, post_p_source, post_p_receipt));
}
