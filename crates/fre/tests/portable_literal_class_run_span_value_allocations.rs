#![forbid(unsafe_code)]

use std::alloc::System;

use fre::{
    PlanKind, PortableBuilder, SearchAccounting, SearchLimits, SearchSessionLimits, SearchWindow,
};
use stats_alloc::{INSTRUMENTED_SYSTEM, Region, Stats, StatsAlloc};

#[global_allocator]
static GLOBAL: &StatsAlloc<System> = &INSTRUMENTED_SYSTEM;

fn span(matched: Option<fre::Match>) -> Option<(usize, usize)> {
    matched.map(|matched| (matched.start(), matched.end()))
}

#[test]
fn generalized_selected_span_values_allocate_nothing() {
    let regex = PortableBuilder::new(r"a[ab]+c")
        .unicode(false)
        .build()
        .expect("generalized selected-span fixture builds");
    assert_eq!(regex.build_report().plan, PlanKind::LiteralClassRunLiteral);
    let haystack = b"!!aabbc!!";
    let absent = b"!!bbbb!!";
    let window = SearchWindow::full(haystack);
    let (_, accounting) = regex
        .find_window(haystack, window, SearchLimits::unlimited())
        .unwrap();
    let SearchAccounting::LiteralClassRunLiteral(accounting) = accounting else {
        panic!("generalized fixture published another accounting family");
    };
    let exact = SearchLimits {
        max_work: u64::try_from(accounting.work).unwrap(),
        max_scratch_bytes: 0,
    };
    let refusing = SearchLimits {
        max_work: exact.max_work - 1,
        max_scratch_bytes: 0,
    };
    let custom = SearchLimits {
        max_work: u64::MAX,
        max_scratch_bytes: 0,
    };
    let invalid = SearchWindow::new(haystack.len(), haystack.len() - 1);
    let guarded = PortableBuilder::new(r"\b[A-B]+T\b")
        .unicode(false)
        .build()
        .expect("guarded selected-span fixture builds");
    let guarded_haystack = b"!AABT!";
    let mut session = regex
        .search_session(SearchSessionLimits::unlimited())
        .expect("generalized selected-span session builds");

    assert_eq!(
        span(
            regex
                .find_window_value(haystack, window, SearchLimits::unlimited())
                .unwrap(),
        ),
        Some((2, 7)),
    );
    assert_eq!(
        span(
            session
                .find_window_value(haystack, window, SearchLimits::unlimited())
                .unwrap(),
        ),
        Some((2, 7)),
    );
    assert_eq!(
        span(
            guarded
                .find_window_value(
                    guarded_haystack,
                    SearchWindow::full(guarded_haystack),
                    SearchLimits::unlimited(),
                )
                .unwrap(),
        ),
        Some((1, 5)),
    );

    let measured = Region::new(GLOBAL);
    for _ in 0..64 {
        assert_eq!(
            span(
                regex
                    .find_window_value(haystack, window, SearchLimits::unlimited())
                    .unwrap(),
            ),
            Some((2, 7)),
        );
        assert_eq!(
            span(
                session
                    .find_window_value(haystack, window, SearchLimits::unlimited())
                    .unwrap(),
            ),
            Some((2, 7)),
        );
        assert_eq!(
            regex
                .find_window_value(
                    absent,
                    SearchWindow::full(absent),
                    SearchLimits::unlimited(),
                )
                .unwrap(),
            None,
        );
        assert_eq!(span(regex.find_window_value(haystack, window, exact).unwrap()), Some((2, 7)));
        assert_eq!(span(regex.find_window_value(haystack, window, custom).unwrap()), Some((2, 7)));
        assert!(regex.find_window_value(haystack, window, refusing).is_err());
        assert!(
            regex
                .find_window_value(haystack, invalid, SearchLimits::unlimited())
                .is_err()
        );
        assert_eq!(
            span(
                guarded
                    .find_window_value(
                        guarded_haystack,
                        SearchWindow::full(guarded_haystack),
                        SearchLimits::unlimited(),
                    )
                    .unwrap(),
            ),
            Some((1, 5)),
        );
    }
    assert_eq!(measured.change(), Stats::default());
}
