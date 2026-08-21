#![forbid(unsafe_code)]

use std::alloc::System;

use fre::{PortableBuilder, SearchAccounting, SearchLimits, SearchSessionLimits, SearchWindow};
use stats_alloc::{INSTRUMENTED_SYSTEM, Region, Stats, StatsAlloc};

#[global_allocator]
static GLOBAL: &StatsAlloc<System> = &INSTRUMENTED_SYSTEM;

#[test]
fn literal_class_run_existence_values_allocate_nothing() {
    let regex = PortableBuilder::new(r"aa[01]+QZ")
        .unicode(false)
        .build()
        .unwrap();
    let suffix = PortableBuilder::new(r"a[01]+TRAILER")
        .unicode(false)
        .build()
        .unwrap();
    let inside = PortableBuilder::new(r"[ab]+aba")
        .unicode(false)
        .build()
        .unwrap();
    let guarded = PortableBuilder::new(r"\b\w+ing\b")
        .unicode(false)
        .build()
        .unwrap();
    let haystack = b"!aa0101QZ!";
    let suffix_haystack = b"!a0101TRAILER!";
    let absent = b"!aa0101XX!";
    let inside_haystack = b"!aababa!";
    let guarded_haystack = b"!testing!";
    let window = SearchWindow::full(haystack);
    let (_, accounting) = regex
        .is_match_window(haystack, window, SearchLimits::unlimited())
        .unwrap();
    let SearchAccounting::LiteralClassRunLiteral(accounting) = accounting else {
        panic!("literal/class-run fixture published another accounting family");
    };
    assert!(accounting.work > 0);
    let exact = SearchLimits {
        max_work: u64::try_from(accounting.work).unwrap(),
        max_scratch_bytes: accounting.scratch_bytes,
    };
    let refusing = SearchLimits {
        max_work: exact.max_work - 1,
        ..exact
    };
    let custom = SearchLimits {
        max_work: u64::MAX,
        max_scratch_bytes: 0,
    };
    let invalid = SearchWindow::new(haystack.len(), haystack.len() - 1);
    let mut session = regex
        .search_session(SearchSessionLimits::unlimited())
        .unwrap();

    assert!(
        regex
            .is_match_window_value(haystack, window, SearchLimits::unlimited())
            .unwrap()
    );
    assert!(
        session
            .is_match_window_value(haystack, window, SearchLimits::unlimited())
            .unwrap()
    );

    let measured = Region::new(GLOBAL);
    for _ in 0..64 {
        assert!(regex.is_match(haystack));
        assert!(suffix.is_match(suffix_haystack));
        assert!(!regex.is_match(absent));
        assert!(inside.is_match(inside_haystack));
        assert!(guarded.is_match(guarded_haystack));
        assert!(
            regex
                .is_match_window_value(haystack, window, SearchLimits::unlimited())
                .unwrap()
        );
        assert!(
            session
                .is_match_window_value(haystack, window, SearchLimits::unlimited())
                .unwrap()
        );
        assert!(
            suffix
                .is_match_window_value(
                    suffix_haystack,
                    SearchWindow::full(suffix_haystack),
                    SearchLimits::unlimited(),
                )
                .unwrap()
        );
        assert!(
            !regex
                .is_match_window_value(
                    absent,
                    SearchWindow::full(absent),
                    SearchLimits::unlimited(),
                )
                .unwrap()
        );
        assert!(
            regex
                .is_match_window_value(haystack, window, exact)
                .unwrap()
        );
        assert!(
            regex
                .is_match_window_value(haystack, window, custom)
                .unwrap()
        );
        assert!(
            regex
                .is_match_window_value(haystack, window, refusing)
                .is_err()
        );
        assert!(
            session
                .is_match_window_value(haystack, invalid, SearchLimits::unlimited())
                .is_err()
        );
        assert!(
            inside
                .is_match_window_value(
                    inside_haystack,
                    SearchWindow::full(inside_haystack),
                    SearchLimits::unlimited(),
                )
                .unwrap()
        );
        assert!(
            guarded
                .is_match_window_value(
                    guarded_haystack,
                    SearchWindow::full(guarded_haystack),
                    SearchLimits::unlimited(),
                )
                .unwrap()
        );
    }
    assert_eq!(measured.change(), Stats::default());
}
