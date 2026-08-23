#![forbid(unsafe_code)]

use std::{alloc::System, hint::black_box};

use fre::{PlanKind, PortableBuilder, SearchAccounting, SearchLimits, SearchWindow};
use stats_alloc::{INSTRUMENTED_SYSTEM, Region, Stats, StatsAlloc};

#[global_allocator]
static GLOBAL: &StatsAlloc<System> = &INSTRUMENTED_SYSTEM;

fn span(matched: Option<fre::Match>) -> Option<(usize, usize)> {
    matched.map(|matched| (matched.start(), matched.end()))
}

#[test]
fn bounded_delimited_ordinary_and_value_facades_allocate_nothing() {
    let regex = PortableBuilder::new(r"(?-u:(?:[a-z]{1,16}/){1,4}DONE)")
        .unicode(false)
        .build()
        .expect("bounded-delimited fixture builds");
    assert_eq!(regex.build_report().plan, PlanKind::RequiredLiteral);
    assert_eq!(
        regex.runtime_implementation_id(),
        "required-literal.bounded-delimited-segment-repeat.v1",
    );

    let immediate = b"a/DONE";
    let barriers = b"DONE!b/DONE!cc/dd/DONE";
    let miss = vec![b'!'; 4_096];
    let mut late = miss.clone();
    late[4_088..].copy_from_slice(b"abc/DONE");
    let window = SearchWindow::full(barriers);
    let (_, accounting) = regex
        .find_window(barriers, window, SearchLimits::unlimited())
        .expect("reported fixture search");
    let SearchAccounting::RequiredLiteral(accounting) = accounting else {
        panic!("bounded-delimited fixture published another accounting family");
    };
    let exact = SearchLimits {
        max_work: accounting.work_upper_bound,
        max_scratch_bytes: 0,
    };
    let invalid = SearchWindow::new(barriers.len(), barriers.len() - 1);

    assert_eq!(span(regex.find(barriers)), Some((5, 11)));
    assert!(regex.is_match(barriers));
    assert_eq!(
        span(
            regex
                .find_window_value(barriers, window, exact)
                .expect("exact value preflight"),
        ),
        Some((5, 11)),
    );

    let measured = Region::new(GLOBAL);
    for _ in 0..64 {
        assert_eq!(
            span(black_box(regex.find(black_box(immediate)))),
            Some((0, 6))
        );
        assert!(black_box(regex.is_match(black_box(immediate))));
        assert_eq!(
            span(
                regex
                    .find_value(black_box(immediate), SearchLimits::unlimited())
                    .expect("bounded-delimited immediate value search"),
            ),
            Some((0, 6)),
        );
        assert!(
            regex
                .is_match_value(black_box(immediate), SearchLimits::unlimited())
                .expect("bounded-delimited immediate value existence"),
        );
        assert_eq!(
            span(black_box(regex.find(black_box(barriers)))),
            Some((5, 11))
        );
        assert!(black_box(regex.is_match(black_box(barriers))));
        assert_eq!(
            span(
                regex
                    .find_window_value(black_box(barriers), window, exact)
                    .expect("bounded-delimited exact value search"),
            ),
            Some((5, 11)),
        );
        assert!(
            regex
                .is_match_window_value(black_box(barriers), window, exact)
                .expect("bounded-delimited exact value existence"),
        );
        assert_eq!(
            span(black_box(regex.find(black_box(&late)))),
            Some((4_088, 4_096))
        );
        assert!(black_box(regex.is_match(black_box(&late))));
        assert_eq!(
            span(
                regex
                    .find_value(black_box(&late), SearchLimits::unlimited())
                    .expect("bounded-delimited late value search"),
            ),
            Some((4_088, 4_096)),
        );
        assert!(
            regex
                .is_match_value(black_box(&late), SearchLimits::unlimited())
                .expect("bounded-delimited late value existence"),
        );
        assert_eq!(black_box(regex.find(black_box(&miss))), None);
        assert!(!black_box(regex.is_match(black_box(&miss))));
        assert_eq!(
            regex
                .find_value(black_box(&miss), SearchLimits::unlimited())
                .expect("bounded-delimited miss value search"),
            None,
        );
        assert!(
            !regex
                .is_match_value(black_box(&miss), SearchLimits::unlimited())
                .expect("bounded-delimited miss value existence"),
        );
        assert!(
            regex
                .find_window_value(barriers, invalid, SearchLimits::unlimited())
                .is_err(),
        );
        assert!(
            regex
                .is_match_window_value(barriers, invalid, SearchLimits::unlimited())
                .is_err(),
        );
    }
    assert_eq!(measured.change(), Stats::default());
}
