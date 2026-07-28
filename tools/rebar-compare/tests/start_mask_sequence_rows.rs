use fre::{
    AggregatePlanIdentity, AggregatePlanKind, FixedAbsoluteDomainDescriptorIdentity,
    FixedAbsoluteDomainOperation,
};
use rebar_compare::{
    current_fre_rebar_aggregate_builder, current_fre_rebar_aggregate_operation_lifecycle,
    current_fre_rebar_validate_aggregate_identity,
};

const PATTERN: &str = r"^.bc(d|e)";

#[test]
fn imported_rsc_matching_anchor_uses_the_same_direct_plan_across_adapter_lifecycles() {
    let patterns = [PATTERN.to_owned()];
    let haystack = b"abcdefghijklmnopqrstuvwxyz";
    let lifecycle = current_fre_rebar_aggregate_operation_lifecycle(
        "count-spans",
        &patterns,
        false,
        false,
        haystack.len(),
    )
    .expect("matching anchored-literal lifecycle");
    assert_eq!(lifecycle.plan(), "aggregate-fixed-absolute-domain");
    assert_eq!(lifecycle.execute(haystack).unwrap(), 4);
    assert_eq!(lifecycle.execute(haystack).unwrap(), 4);

    let regex = current_fre_rebar_aggregate_builder(PATTERN, false, false)
        .build_span_sum()
        .expect("matching anchored-literal facade");
    assert_eq!(
        regex.build_report().plan,
        AggregatePlanKind::FixedAbsoluteDomain
    );
    let AggregatePlanIdentity::FixedAbsoluteDomain(identity) = regex.build_report().plan_identity
    else {
        panic!("matching anchored-literal facade lost its fixed identity");
    };
    assert_eq!(
        identity.kernel.descriptor,
        FixedAbsoluteDomainDescriptorIdentity::StartMaskSequence { width: 4 }
    );
    current_fre_rebar_validate_aggregate_identity(regex.build_report(), false, "count-spans")
        .expect("adapter accepts the closed start-mask identity");
}

#[test]
fn count_lifecycle_accepts_the_operation_typed_start_mask_identity() {
    let patterns = [PATTERN.to_owned()];
    let haystack = b"abcdefghijklmnopqrstuvwxyz";
    let lifecycle = current_fre_rebar_aggregate_operation_lifecycle(
        "count",
        &patterns,
        false,
        false,
        haystack.len(),
    )
    .expect("matching anchored-literal Count lifecycle");
    assert_eq!(lifecycle.plan(), "aggregate-fixed-absolute-domain");
    assert_eq!(lifecycle.execute(haystack).unwrap(), 1);
    assert_eq!(lifecycle.execute(haystack).unwrap(), 1);

    let regex = current_fre_rebar_aggregate_builder(PATTERN, false, false)
        .build_count()
        .expect("matching anchored-literal Count facade");
    let AggregatePlanIdentity::FixedAbsoluteDomain(identity) = regex.build_report().plan_identity
    else {
        panic!("matching anchored-literal Count facade lost its fixed identity");
    };
    assert_eq!(
        identity.kernel.descriptor,
        FixedAbsoluteDomainDescriptorIdentity::StartMaskSequence { width: 4 }
    );
    assert_eq!(
        identity.kernel.operation,
        FixedAbsoluteDomainOperation::Count
    );
    current_fre_rebar_validate_aggregate_identity(regex.build_report(), false, "count")
        .expect("adapter accepts the closed Count start-mask identity");
}
