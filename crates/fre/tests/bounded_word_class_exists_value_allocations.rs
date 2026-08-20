#![forbid(unsafe_code)]

use std::alloc::System;

use fre::{PortableBuilder, SearchAccounting, SearchLimits, SearchSessionLimits, SearchWindow};
use stats_alloc::{INSTRUMENTED_SYSTEM, Region, Stats, StatsAlloc};

#[global_allocator]
static GLOBAL: &StatsAlloc<System> = &INSTRUMENTED_SYSTEM;

#[test]
fn bounded_word_class_existence_values_allocate_nothing() {
    let ascii = PortableBuilder::new(r"(?-u:\b[a!]{1,64}\b)")
        .unicode(false)
        .build()
        .unwrap();
    let unicode = PortableBuilder::new(r"\b[α!]{1,64}\b")
        .unicode(true)
        .build()
        .unwrap();
    let mut ascii_haystack = b"a!".repeat(31);
    ascii_haystack.extend_from_slice(b"a-");
    let unicode_haystack = format!("xx-{}α-", "α!".repeat(31)).into_bytes();
    let absent = b"------------------------------------------------";
    let window = SearchWindow::full(&ascii_haystack);
    let (_, accounting) = ascii
        .is_match_window(&ascii_haystack, window, SearchLimits::unlimited())
        .unwrap();
    let SearchAccounting::UnicodeWordRun(accounting) = accounting else {
        panic!("bounded-word fixture published another accounting family");
    };
    let exact = SearchLimits {
        max_work: accounting.work(),
        max_scratch_bytes: 0,
    };
    let refusing = SearchLimits {
        max_work: accounting.work() - 1,
        max_scratch_bytes: 0,
    };
    let zero_scratch_unmetered = SearchLimits {
        max_work: u64::MAX,
        max_scratch_bytes: 0,
    };
    let invalid = SearchWindow::new(ascii_haystack.len(), ascii_haystack.len() - 1);
    let mut session = unicode
        .search_session(SearchSessionLimits::unlimited())
        .unwrap();

    assert!(
        ascii
            .is_match_value(&ascii_haystack, SearchLimits::unlimited())
            .unwrap()
    );
    assert!(
        session
            .is_match_value_at(&unicode_haystack, 3, SearchLimits::unlimited())
            .unwrap()
    );

    let measured = Region::new(GLOBAL);
    for _ in 0..64 {
        assert!(
            ascii
                .is_match_value(&ascii_haystack, SearchLimits::unlimited())
                .unwrap()
        );
        assert!(
            session
                .is_match_value_at(&unicode_haystack, 3, SearchLimits::unlimited())
                .unwrap()
        );
        assert!(
            ascii
                .is_match_window_value(&ascii_haystack, window, zero_scratch_unmetered)
                .unwrap()
        );
        assert!(
            ascii
                .is_match_window_value(&ascii_haystack, window, exact)
                .unwrap()
        );
        assert!(
            ascii
                .is_match_window_value(&ascii_haystack, window, refusing)
                .is_err()
        );
        assert!(
            !ascii
                .is_match_value(absent, SearchLimits::unlimited())
                .unwrap()
        );
        assert!(
            ascii
                .is_match_window_value(&ascii_haystack, invalid, zero_scratch_unmetered)
                .is_err()
        );
    }
    assert_eq!(measured.change(), Stats::default());
}
