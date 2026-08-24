#![forbid(unsafe_code)]

use std::{alloc::System, hint::black_box};

use fre::{PlanKind, PortableBuilder, SearchLimits, SearchSessionLimits, SearchWindow};
use stats_alloc::{INSTRUMENTED_SYSTEM, Region, Stats, StatsAlloc};

#[global_allocator]
static GLOBAL: &StatsAlloc<System> = &INSTRUMENTED_SYSTEM;

#[test]
fn optional_literal_tail_packed_facades_and_sessions_allocate_nothing() {
    let regex = PortableBuilder::new(r"(?-u:(?:ab|a)??b)")
        .unicode(false)
        .build()
        .expect("optional literal-tail fixture builds");
    assert_eq!(regex.build_report().plan, PlanKind::PackedLiteralSet);
    let hit = b"xxabb--ab--b";
    let miss = b"xxxxxxxxxxxx";
    let window = SearchWindow::new(1, hit.len());
    let expected = regex.find(hit);
    let expected_window = regex
        .find_window_value(hit, window, SearchLimits::unlimited())
        .unwrap();
    let mut ordinary = regex.ordinary_session().unwrap();
    let mut session = regex
        .search_session(SearchSessionLimits::unlimited())
        .unwrap();

    assert!(regex.is_match(hit));
    assert!(!regex.is_match(miss));
    assert_eq!(ordinary.find_at(hit, 0).unwrap(), expected);
    assert_eq!(
        session
            .find_window_value(hit, window, SearchLimits::unlimited())
            .unwrap(),
        expected_window,
    );

    let measured = Region::new(GLOBAL);
    for _ in 0..64 {
        assert!(black_box(regex.is_match(black_box(hit))));
        assert_eq!(black_box(regex.find(black_box(hit))), expected);
        assert!(!black_box(regex.is_match(black_box(miss))));
        assert_eq!(black_box(regex.find(black_box(miss))), None);
        assert_eq!(
            regex
                .find_value(black_box(hit), SearchLimits::unlimited())
                .unwrap(),
            expected,
        );
        assert!(
            regex
                .is_match_value(black_box(hit), SearchLimits::unlimited())
                .unwrap()
        );
        assert_eq!(
            regex
                .find_accounted(black_box(hit), SearchLimits::unlimited())
                .unwrap()
                .0,
            expected,
        );
        assert_eq!(ordinary.find_at(black_box(hit), 0).unwrap(), expected);
        assert!(ordinary.is_match_at(black_box(hit), 0).unwrap());
        assert_eq!(
            session
                .find_window_value(black_box(hit), window, SearchLimits::unlimited())
                .unwrap(),
            expected_window,
        );
        assert!(
            session
                .is_match_window_value(black_box(hit), window, SearchLimits::unlimited())
                .unwrap()
        );
        let mut matches = 0_usize;
        ordinary
            .try_visit_spans(black_box(hit), |_| {
                matches += 1;
                Ok::<bool, ()>(true)
            })
            .unwrap()
            .unwrap();
        assert_eq!(matches, 3);
    }
    assert_eq!(measured.change(), Stats::default());
}
