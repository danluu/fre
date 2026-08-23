#![forbid(unsafe_code)]

use std::alloc::System;

use fre::{NULLABLE_FINITE_TOKEN_REPEAT_PLAN_ID, NULLABLE_OPTIONAL_CHAIN_PLAN_ID, PortableBuilder};
use stats_alloc::{INSTRUMENTED_SYSTEM, Region, Stats, StatsAlloc};

#[global_allocator]
static GLOBAL: &StatsAlloc<System> = &INSTRUMENTED_SYSTEM;

#[test]
fn ordinary_nullable_exists_value_core_allocates_nothing() {
    let optional = PortableBuilder::new(r"(?-u:[ab]{0,3}[cd]{0,2}z)")
        .unicode(false)
        .build()
        .unwrap();
    let finite = PortableBuilder::new(r"(?-u:(?:a|aa|ba){0,3}z)")
        .unicode(false)
        .build()
        .unwrap();
    assert_eq!(
        optional.runtime_implementation_id(),
        NULLABLE_OPTIONAL_CHAIN_PLAN_ID,
    );
    assert_eq!(
        finite.runtime_implementation_id(),
        NULLABLE_FINITE_TOKEN_REPEAT_PLAN_ID,
    );

    let optional_hit = b"xxaacz--z";
    let finite_hit = b"xxaabaz--z";
    let miss = b"xxxxxxxx";
    assert!(optional.is_match(optional_hit));
    assert!(finite.is_match(finite_hit));

    let measured = Region::new(GLOBAL);
    for _ in 0..64 {
        assert!(optional.is_match(optional_hit));
        assert!(!optional.is_match(miss));
        assert!(finite.is_match(finite_hit));
        assert!(!finite.is_match(miss));
    }
    assert_eq!(measured.change(), Stats::default());
}
