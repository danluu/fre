#![forbid(unsafe_code)]

use fre::{PlanKind, PlanSelection, PortableBuilder, PortableRegex, SearchLimits};

fn assert_value_parity(regex: &PortableRegex, haystack: &[u8]) {
    let mut ordinary = regex.ordinary_session().expect("ordinary session binds");
    for start in 0..=haystack.len() {
        let expected_end = regex
            .shortest_match_at_value(haystack, start, SearchLimits::unlimited())
            .expect("immutable endpoint search succeeds");
        let expected_match = regex
            .find_at_value(haystack, start, SearchLimits::unlimited())
            .expect("immutable span search succeeds");
        assert_eq!(
            ordinary.first_acceptance_at(haystack, start),
            Ok(expected_end),
            "endpoint start={start}",
        );
        assert_eq!(
            ordinary.is_match_at(haystack, start),
            Ok(expected_end.is_some()),
            "existence start={start}",
        );
        assert_eq!(
            ordinary.find_at(haystack, start),
            Ok(expected_match),
            "span start={start}",
        );
    }
}

fn visited_spans(regex: &PortableRegex, haystack: &[u8], start: usize) -> Vec<(usize, usize)> {
    let mut ordinary = regex.ordinary_session().expect("ordinary session binds");
    let mut spans = Vec::new();
    assert_eq!(
        ordinary
            .try_visit_spans_at(haystack, start, |matched| {
                spans.push((matched.start(), matched.end()));
                Ok::<bool, ()>(true)
            })
            .expect("ordinary visitor search succeeds"),
        Ok(()),
    );
    spans
}

#[test]
fn compact_canonical_preserves_exact_required_fixed_native_and_unicode_values() {
    let empty = PortableBuilder::new("")
        .unicode(false)
        .build()
        .expect("empty exact literal builds");
    assert_eq!(empty.build_report().plan, PlanKind::ExactLiteral);
    assert_value_parity(&empty, b"x");
    assert_eq!(visited_spans(&empty, b"x", 0), [(0, 0), (1, 1)],);

    let required = PortableBuilder::new(r"(?-u:[a-z]+ZQ)")
        .unicode(false)
        .plan_selection(PlanSelection::ForceRequiredLiteral)
        .build()
        .expect("required-literal fixture builds");
    assert_eq!(required.build_report().plan, PlanKind::RequiredLiteral);
    let required_haystack = b"!ZQ!aaaaZQxxbbZQ";
    assert_value_parity(&required, required_haystack);
    assert_eq!(
        visited_spans(&required, required_haystack, 0),
        [(4, 10), (10, 16)],
    );

    let fixed = PortableBuilder::new(r"Q[ab][cd][ef][gh][ij][kl][mn][op][rs][tu][vw][xy][01]")
        .unicode(false)
        .build()
        .expect("fixed-predicate fixture builds");
    assert_eq!(fixed.build_report().plan, PlanKind::FixedPredicateWord64);
    let fixed_haystack = b"--Qacegikmortvx0--";
    assert_value_parity(&fixed, fixed_haystack);
    assert_eq!(visited_spans(&fixed, fixed_haystack, 0), [(2, 16)],);

    let anchored = PortableBuilder::new(r"(?-u:\A[ab]+Z)")
        .unicode(false)
        .build()
        .expect("anchored native fixture builds");
    assert_eq!(anchored.build_report().plan, PlanKind::ForwardAnchored);
    let anchored_haystack = b"ababZtail";
    assert_value_parity(&anchored, anchored_haystack);
    assert_eq!(visited_spans(&anchored, anchored_haystack, 0), [(0, 5)],);
    assert!(visited_spans(&anchored, anchored_haystack, 1).is_empty());

    let unicode = PortableBuilder::new(r"[A\p{Greek}\x{96EA}\x{10400}]{2,6}?")
        .build()
        .expect("Unicode scalar-run fixture builds");
    assert_eq!(unicode.build_report().plan, PlanKind::UnicodeScalarRun);
    let unicode_haystack = "--Aα雪𐐀A--".as_bytes();
    assert_value_parity(&unicode, unicode_haystack);
    assert_eq!(
        visited_spans(&unicode, unicode_haystack, 0),
        [(2, 5), (5, 12)],
    );
    assert_value_parity(&unicode, b"\xffA\xce\xb1");
}

#[test]
fn compact_canonical_visitor_preserves_empty_progress_stop_error_and_range_order() {
    let empty = PortableBuilder::new("")
        .unicode(false)
        .build()
        .expect("empty exact literal builds");
    let mut ordinary = empty.ordinary_session().expect("ordinary session binds");

    let mut stopped = 0;
    assert_eq!(
        ordinary
            .try_visit_spans(b"xy", |_| {
                stopped += 1;
                Ok::<bool, &'static str>(false)
            })
            .expect("stopped visit succeeds"),
        Ok(()),
    );
    assert_eq!(stopped, 1);

    let mut errored = 0;
    assert_eq!(
        ordinary
            .try_visit_spans(b"xy", |_| {
                errored += 1;
                Err::<bool, _>("callback")
            })
            .expect("callback errors remain inner"),
        Err("callback"),
    );
    assert_eq!(errored, 1);

    let mut invalid_called = false;
    assert!(
        ordinary
            .try_visit_spans_at(b"xy", 3, |_| {
                invalid_called = true;
                Ok::<bool, ()>(true)
            })
            .is_err()
    );
    assert!(!invalid_called);

    assert_eq!(visited_spans(&empty, b"xy", 1), [(1, 1), (2, 2)],);
}
