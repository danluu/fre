#![allow(
    clippy::arithmetic_side_effects,
    reason = "bounded exhaustive generators and test-only callback counters"
)]

use fre::{
    LAZY_DELIMITED_REPEAT_PLAN_ID, LAZY_DELIMITED_REPEAT_SPAN_VISIT_OPERATION_ID,
    LazyDelimitedRepeatSpanVisitError, LazyDelimitedRepeatSpanVisitLimits, PlanKind,
    PortableBuilder, PortableSpanVisitAccounting, PortableSpanVisitError, PortableSpanVisitLimits,
    SearchSessionLimits,
};
use regex::bytes::RegexBuilder;

const PATTERN: &str = r"(.*?,){2}z";

fn portable(pattern: &str) -> fre::PortableRegex {
    PortableBuilder::new(pattern)
        .unicode(false)
        .build()
        .unwrap_or_else(|error| panic!("portable build failed for {pattern:?}: {error}"))
}

fn expected(pattern: &str, haystack: &[u8]) -> Vec<(usize, usize)> {
    RegexBuilder::new(pattern)
        .unicode(false)
        .build()
        .unwrap()
        .find_iter(haystack)
        .map(|matched| (matched.start(), matched.end()))
        .collect()
}

fn visited(regex: &fre::PortableRegex, haystack: &[u8]) -> Vec<(usize, usize)> {
    let mut spans = Vec::new();
    let result = regex
        .try_visit_spans(haystack, PortableSpanVisitLimits::unlimited(), |matched| {
            spans.push((matched.start(), matched.end()));
        })
        .unwrap()
        .expect("eligible visitor");
    assert_eq!(result.matches, spans.len());
    assert_eq!(
        result.span_sum,
        spans
            .iter()
            .map(|&(start, end)| u64::try_from(end - start).unwrap())
            .sum(),
    );
    let PortableSpanVisitAccounting::LazyDelimitedRepeat(accounting) = result.accounting else {
        panic!("wrong visitor family");
    };
    assert_eq!(accounting.identity.plan_id, LAZY_DELIMITED_REPEAT_PLAN_ID);
    assert_eq!(
        accounting.identity.operation_id,
        LAZY_DELIMITED_REPEAT_SPAN_VISIT_OPERATION_ID,
    );
    assert!(accounting.identity.lazy);
    assert!(accounting.identity.exact_repeat);
    assert!(accounting.identity.non_overlapping);
    assert!(!accounting.identity.unicode);
    assert_eq!(accounting.upper_bounds.input_bytes, haystack.len());
    assert_eq!(accounting.actual.matches, result.matches);
    assert_eq!(accounting.actual.span_sum, result.span_sum);
    assert!(accounting.actual.source_reads <= accounting.upper_bounds.source_reads);
    assert!(accounting.actual.work <= accounting.upper_bounds.work);
    spans
}

fn strings(maximum_length: usize, alphabet: &[u8]) -> Vec<Vec<u8>> {
    let mut all = vec![Vec::new()];
    let mut frontier = vec![Vec::new()];
    for _ in 0..maximum_length {
        let mut next = Vec::new();
        for prefix in &frontier {
            for &byte in alphabet {
                let mut value = prefix.clone();
                value.push(byte);
                all.push(value.clone());
                next.push(value);
            }
        }
        frontier = next;
    }
    all
}

#[test]
fn visitor_matches_upstream_for_exhaustive_small_byte_sources() {
    let regex = portable(PATTERN);
    assert_eq!(regex.build_report().plan, PlanKind::K0);
    assert_eq!(regex.runtime_implementation_id(), "k0");
    assert_eq!(
        regex.span_visit_runtime_implementation_id(),
        Some(LAZY_DELIMITED_REPEAT_SPAN_VISIT_OPERATION_ID),
    );
    for haystack in strings(7, &[b'a', b',', b'z', b'\n', 0xFF]) {
        assert_eq!(
            visited(&regex, &haystack),
            expected(PATTERN, &haystack),
            "haystack={haystack:?}",
        );
    }
}

#[test]
fn visitor_handles_lazy_backtracking_barriers_and_nonoverlap() {
    let regex = portable(PATTERN);
    for haystack in [
        b"a,b,c,d,z".as_slice(),
        b"a,zb,z,c,z".as_slice(),
        b"a,b,z\r\nc,d,z".as_slice(),
        b"a,b,za,b,z".as_slice(),
        b"\xff,a,b,z\x80,c,d,z".as_slice(),
        b",z,z,z".as_slice(),
        b"a,b,z\na,b,z\r\na,b,z".as_slice(),
    ] {
        assert_eq!(
            visited(&regex, haystack),
            expected(PATTERN, haystack),
            "haystack={haystack:?}",
        );
    }
}

#[test]
fn retained_session_is_source_independent_and_reusable_after_mutation() {
    let regex = portable(PATTERN);
    let mut session = regex
        .search_session(SearchSessionLimits::unlimited())
        .unwrap();
    let setup = session
        .workspace_setup_accounting()
        .expect("K0 retains its ordinary source-free workspace");
    let mut haystack = b"a,b,z!no-pair".to_vec();
    let address = haystack.as_ptr();
    for replacement in [b"a,b,z!no-pair".as_slice(), b"a,b,x!c,d,z".as_slice()] {
        haystack.clear();
        haystack.extend_from_slice(replacement);
        assert_eq!(haystack.as_ptr(), address);
        let mut actual = Vec::new();
        session
            .try_visit_spans(&haystack, PortableSpanVisitLimits::unlimited(), |matched| {
                actual.push((matched.start(), matched.end()))
            })
            .unwrap()
            .expect("retained visitor");
        assert_eq!(actual, expected(PATTERN, &haystack));
        assert_eq!(session.workspace_setup_accounting(), Some(setup));
    }
}

#[test]
fn typed_refusal_is_pre_callback_and_session_remains_usable() {
    let regex = portable(PATTERN);
    let haystack = b"a,b,z!c,d,z";
    let mut session = regex
        .search_session(SearchSessionLimits::unlimited())
        .unwrap();
    let mut callbacks = 0;
    let error = session
        .try_visit_spans(
            haystack,
            PortableSpanVisitLimits {
                lazy_delimited_repeat: LazyDelimitedRepeatSpanVisitLimits {
                    max_input_bytes: haystack.len() - 1,
                    ..LazyDelimitedRepeatSpanVisitLimits::unlimited()
                },
                ..PortableSpanVisitLimits::unlimited()
            },
            |_| callbacks += 1,
        )
        .unwrap_err();
    assert!(matches!(
        error,
        PortableSpanVisitError::LazyDelimitedRepeat(
            LazyDelimitedRepeatSpanVisitError::InputBytesLimit { .. }
        )
    ));
    assert_eq!(callbacks, 0);

    let mut after = Vec::new();
    session
        .try_visit_spans(haystack, PortableSpanVisitLimits::unlimited(), |matched| {
            after.push((matched.start(), matched.end()))
        })
        .unwrap()
        .expect("visitor remains usable after refusal");
    assert_eq!(after, expected(PATTERN, haystack));
}

#[test]
fn hostile_shapes_return_none_without_callbacks() {
    for pattern in [
        r"(.*,){2}z",
        r"(.+?,){2}z",
        r"(.*?,){1,2}z",
        r"(.*?;){2}zz",
        r"(.*?\n){2}z",
    ] {
        let regex = portable(pattern);
        assert_eq!(regex.span_visit_runtime_implementation_id(), None);
        let mut callbacks = 0;
        let result = regex
            .try_visit_spans(
                b"a,b,z\ninvalid\xffbytes",
                PortableSpanVisitLimits::unlimited(),
                |_| callbacks += 1,
            )
            .unwrap();
        assert_eq!(result, None, "pattern={pattern:?}");
        assert_eq!(callbacks, 0, "pattern={pattern:?}");
    }
}
