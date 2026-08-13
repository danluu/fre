#![forbid(unsafe_code)]

use fre::{PlanKind, PortableBuilder, SearchAccounting, SearchLimits};

#[test]
fn root_finite_literals_keep_native_precedence_but_embedded_literals_share_k0() {
    let root = PortableBuilder::new(r"(?:bar|baz|foo)")
        .unicode(false)
        .build()
        .expect("root finite literals build");
    let root_report = root.build_report();
    assert_eq!(root_report.plan, PlanKind::PackedLiteralSet);
    assert_eq!(root.runtime_implementation_id(), "packed-literal-set");
    assert!(root_report.lowering.is_none());
    assert_eq!((root_report.states, root_report.edges), (0, 0));

    let embedded = PortableBuilder::new(r"(?:bar|baz|foo)+")
        .unicode(false)
        .build()
        .expect("embedded literal alternation builds");
    let embedded_report = embedded.build_report();
    assert_eq!(embedded_report.plan, PlanKind::K0);
    assert_eq!(embedded.runtime_implementation_id(), "k0");
    let lowering = embedded_report
        .lowering
        .expect("embedded direct literal alternation reaches shared lowering");
    assert_eq!((lowering.states(), lowering.edges()), (7, 9));
    assert_eq!((embedded_report.states, embedded_report.edges), (7, 9));

    let (root_match, root_search) = root
        .find(b"xxbazbarfoo!", SearchLimits::unlimited())
        .expect("root finite search");
    let (embedded_match, embedded_search) = embedded
        .find(b"xxbazbarfoo!", SearchLimits::unlimited())
        .expect("embedded K0 search");
    assert_eq!(
        root_match.map(|matched| (matched.start(), matched.end())),
        Some((2, 5))
    );
    assert_eq!(
        embedded_match.map(|matched| (matched.start(), matched.end())),
        Some((2, 11))
    );
    assert!(matches!(root_search, SearchAccounting::PackedLiteralSet(_)));
    assert!(matches!(embedded_search, SearchAccounting::K0(_)));
}
