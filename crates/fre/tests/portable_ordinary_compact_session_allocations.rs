#![forbid(unsafe_code)]

use std::{alloc::System, hint::black_box};

use fre::{PlanKind, PlanSelection, PortableBuilder, PortableRegex};
use stats_alloc::{INSTRUMENTED_SYSTEM, Region, Stats, StatsAlloc};

#[global_allocator]
static GLOBAL: &StatsAlloc<System> = &INSTRUMENTED_SYSTEM;

fn assert_construction_allocates_nothing(regex: &PortableRegex) {
    let measured = Region::new(GLOBAL);
    let ordinary = black_box(regex.ordinary_session().expect("ordinary session binds"));
    black_box(&ordinary);
    let change = measured.change();
    drop(measured);
    drop(ordinary);
    assert_eq!(change, Stats::default());
}

fn assert_steady_calls_allocate_nothing(regex: &PortableRegex, haystack: &[u8]) {
    let mut ordinary = regex.ordinary_session().expect("ordinary session binds");
    let measured = Region::new(GLOBAL);
    for _ in 0..64 {
        let matched = black_box(
            ordinary
                .is_match_at(black_box(haystack), 0)
                .expect("existence succeeds"),
        );
        let endpoint = black_box(
            ordinary
                .first_acceptance_at(black_box(haystack), 0)
                .expect("endpoint succeeds"),
        );
        let span = black_box(
            ordinary
                .find_at(black_box(haystack), 0)
                .expect("span succeeds"),
        );
        assert_eq!(matched, endpoint.is_some());
        assert_eq!(matched, span.is_some());

        let mut visits = 0_usize;
        assert_eq!(
            ordinary
                .try_visit_spans(black_box(haystack), |_| {
                    visits += 1;
                    Ok::<bool, ()>(true)
                })
                .expect("visitor search succeeds"),
            Ok(()),
        );
        black_box(visits);
    }
    assert_eq!(measured.change(), Stats::default());
}

#[test]
fn compact_canonical_construction_and_steady_calls_allocate_nothing() {
    let empty = PortableBuilder::new("")
        .unicode(false)
        .build()
        .expect("empty exact literal builds");
    assert_eq!(empty.build_report().plan, PlanKind::ExactLiteral);

    let required = PortableBuilder::new(r"(?-u:[a-z]+ZQ)")
        .unicode(false)
        .plan_selection(PlanSelection::ForceRequiredLiteral)
        .build()
        .expect("required-literal fixture builds");
    assert_eq!(required.build_report().plan, PlanKind::RequiredLiteral);

    let fixed = PortableBuilder::new(r"Q[ab][cd][ef][gh][ij][kl][mn][op][rs][tu][vw][xy][01]")
        .unicode(false)
        .build()
        .expect("fixed-predicate fixture builds");
    assert_eq!(fixed.build_report().plan, PlanKind::FixedPredicateWord64);

    let anchored = PortableBuilder::new(r"(?-u:\A[ab]+Z)")
        .unicode(false)
        .build()
        .expect("anchored native fixture builds");
    assert_eq!(anchored.build_report().plan, PlanKind::ForwardAnchored);

    let unicode = PortableBuilder::new(r"[A\p{Greek}\x{96EA}\x{10400}]{2,6}?")
        .build()
        .expect("Unicode scalar-run fixture builds");
    assert_eq!(unicode.build_report().plan, PlanKind::UnicodeScalarRun);

    for regex in [&empty, &required, &fixed, &anchored, &unicode] {
        assert_construction_allocates_nothing(regex);
    }

    for (regex, haystack) in [
        (&empty, b"xy".as_slice()),
        (&required, b"!ZQ!aaaaZQxxbbZQ".as_slice()),
        (&fixed, b"--Qacegikmortvx0--".as_slice()),
        (&anchored, b"ababZtail".as_slice()),
        (&unicode, "--Aα雪𐐀A--".as_bytes()),
    ] {
        assert_steady_calls_allocate_nothing(regex, haystack);
    }
}
