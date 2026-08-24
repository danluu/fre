#![forbid(unsafe_code)]

use std::alloc::System;

use fre::{
    NULLABLE_FINITE_TOKEN_REPEAT_PLAN_ID, NULLABLE_OPTIONAL_CHAIN_PLAN_ID, PortableBuilder,
    SearchLimits,
};
use stats_alloc::{INSTRUMENTED_SYSTEM, Region, Stats, StatsAlloc};

#[global_allocator]
static GLOBAL: &StatsAlloc<System> = &INSTRUMENTED_SYSTEM;

#[test]
fn ordinary_nullable_exists_and_finite_span_value_cores_allocate_nothing() {
    let optional = PortableBuilder::new(r"(?-u:[ab]{0,3}[cd]{0,2}z)")
        .unicode(false)
        .build()
        .unwrap();
    let finite = PortableBuilder::new(r"(?-u:(?:a|aa|ba){0,3}z)")
        .unicode(false)
        .build()
        .unwrap();
    let maximum_token = "a".repeat(64);
    let maximum_pattern = format!(r"(?-u:(?:{maximum_token}){{0,8}}z)");
    let maximum = PortableBuilder::new(&maximum_pattern)
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
    assert_eq!(
        maximum.runtime_implementation_id(),
        NULLABLE_FINITE_TOKEN_REPEAT_PLAN_ID,
    );

    let optional_hit = b"xxaacz--z";
    let finite_hit = b"xxaabaz--z";
    let mut maximum_hit = b"xx".to_vec();
    for _ in 0..8 {
        maximum_hit.extend_from_slice(maximum_token.as_bytes());
    }
    maximum_hit.push(b'z');
    let miss = b"xxxxxxxx";
    assert!(optional.is_match(optional_hit));
    assert!(finite.is_match(finite_hit));
    assert!(finite.find(finite_hit).is_some());
    assert!(
        finite
            .find_value(finite_hit, SearchLimits::unlimited())
            .unwrap()
            .is_some()
    );
    assert!(maximum.find(&maximum_hit).is_some());

    let measured = Region::new(GLOBAL);
    for _ in 0..64 {
        assert!(optional.is_match(optional_hit));
        assert!(!optional.is_match(miss));
        assert!(finite.is_match(finite_hit));
        assert!(!finite.is_match(miss));
        assert!(finite.find(finite_hit).is_some());
        assert!(finite.find(miss).is_none());
        assert!(
            finite
                .find_value(finite_hit, SearchLimits::unlimited())
                .unwrap()
                .is_some()
        );
        assert!(
            finite
                .find_value(miss, SearchLimits::unlimited())
                .unwrap()
                .is_none()
        );
        assert!(maximum.find(&maximum_hit).is_some());
        assert!(maximum.find(miss).is_none());
    }
    assert_eq!(measured.change(), Stats::default());
}
