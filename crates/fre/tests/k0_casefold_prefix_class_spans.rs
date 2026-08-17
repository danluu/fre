use fre::{
    K0_CASEFOLD_PREFIX_CLASS_PLAN_ID, K0_CASEFOLD_PREFIX_CLASS_SPAN_VISIT_OPERATION_ID,
    K0CasefoldPrefixClassSpanVisitError, PortableBuilder, PortableSpanVisitAccounting,
    PortableSpanVisitError, PortableSpanVisitLimits, RustProfile,
};
use regex::bytes::RegexBuilder;

fn portable(pattern: &str) -> fre::PortableRegex {
    let mut profile = RustProfile::rebar_1_12_4();
    profile.options.unicode = false;
    profile.options.case_insensitive = true;
    PortableBuilder::new(pattern.to_string())
        .profile(profile)
        .build()
        .unwrap()
}

fn reference(pattern: &str, haystack: &[u8]) -> Vec<(usize, usize)> {
    RegexBuilder::new(pattern)
        .unicode(false)
        .case_insensitive(true)
        .build()
        .unwrap()
        .find_iter(haystack)
        .map(|matched| (matched.start(), matched.end()))
        .collect()
}

#[test]
fn target_shape_routes_and_matches_rust_bytes() {
    let pattern = r"Sher[a-z]+|Hol[a-z]+";
    let regex = portable(pattern);
    assert_eq!(
        regex.span_visit_runtime_implementation_id(),
        Some(K0_CASEFOLD_PREFIX_CLASS_SPAN_VISIT_OPERATION_ID)
    );
    for haystack in [
        b"Sherlock Holmes! Holdup--Sher".as_slice(),
        b"SHERLOCK hOlMeS holdup shERx".as_slice(),
        b"\xffSherlock\x80HOLMES\xfeSher".as_slice(),
        b"sssSHERaaaaHOLzzSherHolmes".as_slice(),
    ] {
        let expected = reference(pattern, haystack);
        let mut actual = Vec::new();
        let result = regex
            .try_visit_spans(haystack, PortableSpanVisitLimits::unlimited(), |matched| {
                actual.push((matched.start(), matched.end()));
            })
            .unwrap()
            .expect("target retains direct visitor");
        assert_eq!(expected, actual);
        assert_eq!(expected.len(), result.matches);
        let PortableSpanVisitAccounting::K0CasefoldPrefixClass(accounting) = result.accounting
        else {
            panic!("target retained the wrong visitor accounting")
        };
        assert_eq!(
            K0_CASEFOLD_PREFIX_CLASS_PLAN_ID,
            accounting.identity.plan_id
        );
        assert_eq!(
            K0_CASEFOLD_PREFIX_CLASS_SPAN_VISIT_OPERATION_ID,
            accounting.identity.operation_id
        );
        assert_eq!(haystack.len(), accounting.upper_bounds.input_bytes);
        assert_eq!(result.matches, accounting.actual.matches);
        assert_eq!(result.span_sum, accounting.actual.span_sum);
    }
}

#[test]
fn source_order_and_nonoverlap_match_rust_bytes_over_generated_inputs() {
    let pattern = r"Ab[b]+|Cd[b-z]+";
    let regex = portable(pattern);
    let alphabet = [b'A', b'a', b'B', b'b', b'Q', b'q', b'Z', b'z', b'-', 0xff];
    let mut state = 0x9e37_79b9_u32;
    for length in 0..48 {
        for _ in 0..64 {
            let mut haystack = Vec::with_capacity(length);
            for _ in 0..length {
                state = state.wrapping_mul(1_664_525).wrapping_add(1_013_904_223);
                haystack.push(alphabet[(state as usize) % alphabet.len()]);
            }
            let expected = reference(pattern, &haystack);
            let mut actual = Vec::new();
            regex
                .try_visit_spans(&haystack, PortableSpanVisitLimits::unlimited(), |matched| {
                    actual.push((matched.start(), matched.end()))
                })
                .unwrap()
                .expect("generated shape retains direct visitor");
            assert_eq!(expected, actual, "haystack {haystack:?}");
        }
    }
}

#[test]
fn one_below_refuses_before_callbacks() {
    let regex = portable(r"Sher[a-z]+|Hol[a-z]+");
    let haystack = b"SHERLOCK Holmes";
    let complete = regex
        .try_visit_spans(haystack, PortableSpanVisitLimits::unlimited(), |_| {})
        .unwrap()
        .unwrap();
    let PortableSpanVisitAccounting::K0CasefoldPrefixClass(accounting) = complete.accounting else {
        panic!("target retained the wrong visitor accounting")
    };
    let mut limits = PortableSpanVisitLimits::unlimited();
    limits.k0_casefold_prefix_class.max_work = accounting.upper_bounds.work - 1;
    let mut callbacks = 0;
    let error = regex
        .try_visit_spans(haystack, limits, |_| callbacks += 1)
        .unwrap_err();
    assert!(matches!(
        error,
        PortableSpanVisitError::K0CasefoldPrefixClass(
            K0CasefoldPrefixClassSpanVisitError::Resource {
                resource: "work units",
                ..
            }
        )
    ));
    assert_eq!(0, callbacks);
}
