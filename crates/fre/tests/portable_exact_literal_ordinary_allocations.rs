#![forbid(unsafe_code)]

use std::{alloc::System, hint::black_box};

use fre::{PlanKind, PortableBuilder};
use stats_alloc::{INSTRUMENTED_SYSTEM, Region, Stats, StatsAlloc};

#[global_allocator]
static GLOBAL: &StatsAlloc<System> = &INSTRUMENTED_SYSTEM;

#[test]
fn exact_literal_ordinary_facades_and_worker_allocate_nothing() {
    let literal = PortableBuilder::new("needle")
        .unicode(false)
        .build()
        .expect("exact literal fixture builds");
    let one_byte = PortableBuilder::new("a")
        .unicode(false)
        .build()
        .expect("one-byte literal fixture builds");
    let empty = PortableBuilder::new("")
        .unicode(false)
        .build()
        .expect("empty literal fixture builds");
    for regex in [&literal, &one_byte, &empty] {
        assert_eq!(regex.build_report().plan, PlanKind::ExactLiteral);
    }

    let measured = Region::new(GLOBAL);
    for _ in 0..64 {
        assert!(black_box(literal.is_match(black_box(b"--needle--"))));
        assert_eq!(
            black_box(literal.find(black_box(b"--needle--")))
                .map(|matched| (matched.start(), matched.end())),
            Some((2, 8)),
        );
        assert!(!black_box(literal.is_match(black_box(b"--need--"))));
        assert_eq!(black_box(literal.find(black_box(b"--need--"))), None);
        assert!(black_box(one_byte.is_match(black_box(b"\xffa"))));
        assert_eq!(
            black_box(one_byte.find(black_box(b"\xffa")))
                .map(|matched| (matched.start(), matched.end())),
            Some((1, 2)),
        );
        assert!(black_box(empty.is_match(black_box(b"\xff"))));
        assert_eq!(
            black_box(empty.find(black_box(b"\xff")))
                .map(|matched| (matched.start(), matched.end())),
            Some((0, 0)),
        );

        let mut ordinary = black_box(literal.ordinary_session().unwrap());
        assert!(black_box(
            ordinary
                .is_match_at(black_box(b"--needle--needle"), 0)
                .unwrap()
        ));
        assert_eq!(
            black_box(
                ordinary
                    .first_acceptance_at(black_box(b"--needle--needle"), 0)
                    .unwrap()
            ),
            Some(8),
        );
        assert_eq!(
            black_box(ordinary.find_at(black_box(b"--needle--needle"), 0).unwrap())
                .map(|matched| (matched.start(), matched.end())),
            Some((2, 8)),
        );
        let mut visits = 0;
        assert_eq!(
            ordinary
                .try_visit_spans(black_box(b"--needle--needle"), |_| {
                    visits += 1;
                    Ok::<bool, ()>(true)
                })
                .unwrap(),
            Ok(()),
        );
        assert_eq!(visits, 2);
        assert_eq!(
            ordinary
                .count_positive_width_selected_ends_at(black_box(b"--needle--needle"), 0)
                .unwrap(),
            Some(2),
        );
    }
    assert_eq!(measured.change(), Stats::default());
}
