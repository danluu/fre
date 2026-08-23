#![forbid(unsafe_code)]

use std::alloc::System;

use fre::{PlanKind, PortableBuilder};
use stats_alloc::{INSTRUMENTED_SYSTEM, Region, Stats, StatsAlloc};

#[global_allocator]
static GLOBAL: &StatsAlloc<System> = &INSTRUMENTED_SYSTEM;

fn build(pattern: &str) -> fre::PortableRegex {
    let regex = PortableBuilder::new(pattern)
        .unicode(false)
        .build()
        .unwrap();
    assert_eq!(regex.build_report().plan, PlanKind::PureByteClassRepeat);
    assert_eq!(
        regex.runtime_implementation_id(),
        fre::PURE_BYTE_CLASS_REPEAT_PLAN_ID,
    );
    regex
}

fn span(matched: Option<fre::Match>) -> Option<(usize, usize)> {
    matched.map(|matched| (matched.start(), matched.end()))
}

#[test]
fn pure_byte_class_ordinary_full_values_allocate_nothing() {
    let first_exists = build("(?-u:[aceg])+");
    let measured_first_exists = Region::new(GLOBAL);
    assert!(first_exists.is_match(b"!!!!!!!!acegg!!!!!!!!"));
    assert_eq!(measured_first_exists.change(), Stats::default());
    drop(measured_first_exists);

    let first_find = build("(?-u:[aceg])+?");
    let measured_first_find = Region::new(GLOBAL);
    assert_eq!(
        span(first_find.find(b"!!!!!!!!!!!!!!!!\xff\x80acegg!!!!!!!!")),
        Some((18, 19)),
    );
    assert_eq!(measured_first_find.change(), Stats::default());
    drop(measured_first_find);

    let greedy = build("(?-u:[aceg])+");
    let lazy = build("(?-u:[\\x80-\\xff])+?");
    let all = build("(?s-u:.)+");

    let greedy_haystack = b"!!!!!!!!acegg!!!!!!!!";
    let lazy_haystack = b"!!!!!!!!\xff\x80!!!!!!!!";
    let all_haystack = b"\0abc\xff";
    assert_eq!(span(greedy.find(greedy_haystack)), Some((8, 13)),);
    assert_eq!(span(lazy.find(lazy_haystack)), Some((8, 9)));
    assert_eq!(span(all.find(all_haystack)), Some((0, 5)));

    let measured = Region::new(GLOBAL);
    for _ in 0..64 {
        assert!(greedy.is_match(greedy_haystack));
        assert_eq!(span(greedy.find(greedy_haystack)), Some((8, 13)),);
        assert!(!greedy.is_match(b"!!!!!!!!!!!!!!!!"));
        assert_eq!(greedy.find(b"!!!!!!!!!!!!!!!!"), None);

        assert!(lazy.is_match(lazy_haystack));
        assert_eq!(span(lazy.find(lazy_haystack)), Some((8, 9)));
        assert!(!lazy.is_match(b"!!!!!!!!!!!!!!!!"));
        assert_eq!(lazy.find(b"!!!!!!!!!!!!!!!!"), None);

        assert!(all.is_match(all_haystack));
        assert_eq!(span(all.find(all_haystack)), Some((0, 5)));
        assert!(!all.is_match(b""));
        assert_eq!(all.find(b""), None);
    }
    assert_eq!(measured.change(), Stats::default());
}
