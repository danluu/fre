use fre::{
    AggregateBuildAccounting, AggregateExecutionDetails, AggregateOperationPhysicalRoute,
    AggregatePlanKind,
};
use rebar_compare::{
    current_fre_rebar_aggregate_builder, current_fre_rebar_aggregate_operation_lifecycle,
    current_fre_rebar_count_run_limits,
};
use sha2::Digest;

const PATTERN: &str = "Шерлок Холмс";
const PATTERN_SHA256: &str = "192672866949818d8c8ea7089c9e622801bd763489f0314c004a459c616cc9b1";

fn semantic_fixture() -> Vec<u8> {
    let mut haystack = vec![0xFF, 0x80];
    haystack.extend_from_slice(
        "ШЕРЛОК ХОЛМС|шерлок холмс|Шерлок Холмс|шЕрЛоК хОлМс|Шерлок Холм".as_bytes(),
    );
    haystack.extend_from_slice(&[0xF4, 0x90, 0x80, 0x80]);
    haystack
}

fn scale_fixture(len: usize) -> Vec<u8> {
    let variants = [
        "ШЕРЛОК ХОЛМС".as_bytes(),
        "шерлок холмс".as_bytes(),
        "шЕрЛоК хОлМс".as_bytes(),
    ];
    let mut haystack = vec![b'x'; len];
    let tail_offset = len.checked_sub(101).unwrap();
    for (offset, variant) in [37, len / 2, tail_offset].into_iter().zip(variants) {
        let end = offset.checked_add(variant.len()).unwrap();
        haystack
            .get_mut(offset..end)
            .unwrap()
            .copy_from_slice(variant);
    }
    haystack[0] = 0xFF;
    let last = len.checked_sub(1).unwrap();
    haystack[last] = 0x80;
    haystack
}

#[test]
fn casefold_literal_facade_retains_scalar_verification_and_operation_lifecycle() {
    assert_eq!(
        format!("{:x}", sha2::Sha256::digest(PATTERN.as_bytes())),
        PATTERN_SHA256
    );
    let haystack = semantic_fixture();
    let oracle = regex::bytes::RegexBuilder::new(PATTERN)
        .unicode(true)
        .case_insensitive(true)
        .build()
        .unwrap();
    let expected = oracle.find_iter(&haystack).count();
    assert_eq!(expected, 4);

    let lifecycle = current_fre_rebar_aggregate_operation_lifecycle(
        "count",
        &[PATTERN.to_string()],
        true,
        true,
        haystack.len(),
    )
    .unwrap();
    assert_eq!(lifecycle.plan(), "aggregate-unicode-folded-literal-v3");
    assert_eq!(lifecycle.execute(&haystack).unwrap(), 4);
    assert_eq!(lifecycle.execute(&haystack).unwrap(), 4);

    let regex = current_fre_rebar_aggregate_builder(PATTERN, true, true)
        .build_count()
        .unwrap();
    assert_eq!(
        regex.build_report().plan,
        AggregatePlanKind::ContinuationProgram
    );
    let AggregateBuildAccounting::Continuation(compile) = regex.build_report().build else {
        panic!("case-fold literal selected a non-continuation build")
    };
    assert_eq!(
        (compile.required_suffixes, compile.required_suffix_bytes),
        (3, 7)
    );

    let limits = current_fre_rebar_count_run_limits(haystack.len(), &regex).unwrap();
    let result = regex.count(&haystack, limits).unwrap();
    assert_eq!(result.value(), 4);
    let AggregateExecutionDetails::Continuation {
        certificate,
        accounting,
    } = result.report().details()
    else {
        panic!("case-fold literal selected a non-continuation execution")
    };
    assert_eq!(
        certificate.physical_route,
        AggregateOperationPhysicalRoute::RequiredSuffixRows
    );
    assert!(accounting.work <= certificate.work_bound);

    for len in [613_423, 1_570_556] {
        let haystack = scale_fixture(len);
        let expected = oracle.find_iter(&haystack).count();
        assert_eq!(expected, 3);
        let limits = current_fre_rebar_count_run_limits(haystack.len(), &regex).unwrap();
        let result = regex.count(&haystack, limits).unwrap();
        assert_eq!(result.value(), u64::try_from(expected).unwrap());
        let AggregateExecutionDetails::Continuation {
            certificate,
            accounting,
        } = result.report().details()
        else {
            panic!("case-fold literal selected a non-continuation execution")
        };
        assert_eq!(
            certificate.physical_route,
            AggregateOperationPhysicalRoute::RequiredSuffixRows
        );
        assert!(accounting.work <= certificate.work_bound);
        assert!(accounting.state_evaluations < haystack.len());
    }
}
