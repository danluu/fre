#![forbid(unsafe_code)]

use fre::{PlanKind, PortableBuilder, SearchLimits};
#[cfg(not(feature = "static-dispatch"))]
use fre::{
    BuildLimits, PortableFindIterRunLimits, SearchAccounting, SearchSessionLimits, SearchWindow,
};

const PATTERN: &str = r"(?:agggtaaa|tttaccct)";
const INCUMBENT_ID: &str = "packed-literal-set";
#[cfg(not(feature = "static-dispatch"))]
const UNIFORM_ID: &str = "packed-literal-set.uniform-word64-search.v1";

fn span(matched: Option<fre::Match>) -> Option<(usize, usize)> {
    matched.map(|matched| (matched.start(), matched.end()))
}

#[test]
#[cfg(not(feature = "static-dispatch"))]
fn portable_find_windows_and_reused_iteration_share_the_uniform_runtime() {
    let regex = PortableBuilder::new(PATTERN)
        .unicode(false)
        .build()
        .expect("eligible finite language");
    assert_eq!(regex.build_report().plan, PlanKind::PackedLiteralSet);
    assert_eq!(regex.runtime_implementation_id(), UNIFORM_ID);

    let haystack = b"__agggtaaaagggtaaa--tttaccct__";
    assert_eq!(
        span(
            regex
                .find_value(haystack, SearchLimits::unlimited())
                .unwrap()
        ),
        Some((2, 10))
    );
    assert_eq!(
        span(
            regex
                .find_at_value(haystack, 3, SearchLimits::unlimited())
                .unwrap()
        ),
        Some((10, 18))
    );
    assert_eq!(
        span(
            regex
                .find_window_value(
                    haystack,
                    SearchWindow::new(3, 18),
                    SearchLimits::unlimited(),
                )
                .unwrap()
        ),
        Some((10, 18))
    );
    let (_, accounting) = regex.find(haystack, SearchLimits::unlimited()).unwrap();
    let SearchAccounting::PackedLiteralSet(accounting) = accounting else {
        panic!("finite language lost packed accounting")
    };
    assert!(!accounting.simd_eligible_length);
    assert!(!accounting.factored_columns);

    let mut session = regex
        .search_session(SearchSessionLimits::unlimited())
        .unwrap();
    assert_eq!(session.runtime_implementation_id(), UNIFORM_ID);
    let spans = session
        .find_iter_value(haystack, PortableFindIterRunLimits::unlimited())
        .map(|matched| span(Some(matched.unwrap())).unwrap())
        .collect::<Vec<_>>();
    assert_eq!(spans, [(2, 10), (10, 18), (20, 28)]);
}

#[test]
#[cfg(not(feature = "static-dispatch"))]
fn facade_residual_persistent_limit_preserves_the_incumbent_fallback() {
    let mut incumbent_limits = BuildLimits::default();
    incumbent_limits.packed_literal_set.max_persistent_bytes = 2_047;
    let incumbent = PortableBuilder::new(PATTERN)
        .unicode(false)
        .limits(incumbent_limits)
        .build()
        .expect("incumbent fits below the uniform table");
    assert_eq!(incumbent.runtime_implementation_id(), INCUMBENT_ID);

    let mut outer_limited = BuildLimits::default();
    outer_limited.max_persistent_bytes = incumbent.build_report().charged_persistent_bytes;
    let rebuilt = PortableBuilder::new(PATTERN)
        .unicode(false)
        .limits(outer_limited)
        .build()
        .expect("facade residual cap admits the incumbent");
    assert_eq!(rebuilt.runtime_implementation_id(), INCUMBENT_ID);
    assert_eq!(
        rebuilt.build_report().charged_persistent_bytes,
        incumbent.build_report().charged_persistent_bytes
    );
}

#[test]
#[cfg(feature = "static-dispatch")]
fn portable_static_dispatch_keeps_the_incumbent_identity() {
    let regex = PortableBuilder::new(PATTERN)
        .unicode(false)
        .build()
        .expect("static finite language");
    assert_eq!(regex.build_report().plan, PlanKind::PackedLiteralSet);
    assert_eq!(regex.runtime_implementation_id(), INCUMBENT_ID);
    assert_eq!(
        span(
            regex
                .find_value(b"__agggtaaa", SearchLimits::unlimited())
                .unwrap()
        ),
        Some((2, 10))
    );
}
