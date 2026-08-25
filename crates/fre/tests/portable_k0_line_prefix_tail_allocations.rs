#![forbid(unsafe_code)]

use std::alloc::System;

use fre::{PlanKind, PortableBuilder};
use regex::bytes::RegexBuilder;
use stats_alloc::{INSTRUMENTED_SYSTEM, Region, Stats, StatsAlloc};

#[global_allocator]
static GLOBAL: &StatsAlloc<System> = &INSTRUMENTED_SYSTEM;

#[test]
fn ordinary_line_prefix_tail_is_differential_and_cold_allocation_free() {
    let pattern = r"(?m)^Subject:[^\r\n]*$";
    let find_regex = PortableBuilder::new(pattern)
        .unicode(false)
        .build()
        .unwrap();
    let exists_regex = PortableBuilder::new(pattern)
        .unicode(false)
        .build()
        .unwrap();
    assert_eq!(find_regex.build_report().plan, PlanKind::K0);
    assert_eq!(exists_regex.build_report().plan, PlanKind::K0);

    let mut late = vec![b'x'; 4_093];
    late.extend_from_slice(b"\nSubject: deterministic value\n");
    let mut rejected_then_late = vec![b'x'; 1_024];
    rejected_then_late.extend_from_slice(
        b"\nSubject: rejected CR\r\nnoise\nSubject: accepted\n",
    );
    let absent = vec![b'x'; 4_127];
    let upstream = RegexBuilder::new(pattern)
        .unicode(false)
        .build()
        .unwrap();
    let expected_late = upstream
        .find(&late)
        .map(|matched| (matched.start(), matched.end()));
    let expected_rejected_then_late = upstream
        .find(&rejected_then_late)
        .map(|matched| (matched.start(), matched.end()));
    assert_eq!(expected_late, Some((4_094, 4_122)));
    assert_eq!(expected_rejected_then_late, Some((1_053, 1_070)));

    let cold = Region::new(GLOBAL);
    assert_eq!(
        find_regex
            .find(&late)
            .map(|matched| (matched.start(), matched.end())),
        expected_late,
    );
    assert_eq!(find_regex.find(&absent), None);
    assert_eq!(
        find_regex
            .find(&rejected_then_late)
            .map(|matched| (matched.start(), matched.end())),
        expected_rejected_then_late,
    );
    assert!(exists_regex.is_match(&late));
    assert!(!exists_regex.is_match(&absent));
    assert!(exists_regex.is_match(&rejected_then_late));
    assert_eq!(cold.change(), Stats::default());
}

#[test]
fn ordinary_open_line_tail_existence_is_differential_and_cold_allocation_free() {
    let pattern = r"(?m)^Subject:(?-u:.)*$";
    let exists_regex = PortableBuilder::new(pattern)
        .unicode(false)
        .build()
        .unwrap();
    assert_eq!(exists_regex.build_report().plan, PlanKind::K0);

    let mut late_with_long_tail = vec![b'x'; 4_093];
    late_with_long_tail.extend_from_slice(b"\nSubject:");
    late_with_long_tail.extend(std::iter::repeat_n(b'x', 4_096));
    late_with_long_tail.push(b'\r');
    let absent = vec![b'x'; 8_197];
    let upstream = RegexBuilder::new(pattern)
        .unicode(false)
        .build()
        .unwrap();
    assert!(upstream.is_match(&late_with_long_tail));
    assert!(!upstream.is_match(&absent));

    let cold = Region::new(GLOBAL);
    assert!(exists_regex.is_match(&late_with_long_tail));
    assert!(!exists_regex.is_match(&absent));
    assert_eq!(cold.change(), Stats::default());
}

#[test]
fn ordinary_class_plus_corridor_is_differential_and_cold_allocation_free() {
    let pattern = r"(?-u:[a-z]+MID[0-9]+)";
    let find_regex = PortableBuilder::new(pattern)
        .unicode(false)
        .build()
        .unwrap();
    let exists_regex = PortableBuilder::new(pattern)
        .unicode(false)
        .build()
        .unwrap();
    assert_eq!(find_regex.build_report().plan, PlanKind::K0);
    assert_eq!(exists_regex.build_report().plan, PlanKind::K0);

    let mut late = vec![b'!'; 4_093];
    late.extend_from_slice(b"alphabeticMID12345");
    let absent = vec![b'!'; 4_127];
    let upstream = RegexBuilder::new(pattern)
        .unicode(false)
        .build()
        .unwrap();
    let expected_late = upstream
        .find(&late)
        .map(|matched| (matched.start(), matched.end()));
    assert_eq!(expected_late, Some((4_093, 4_111)));

    let cold = Region::new(GLOBAL);
    assert_eq!(
        find_regex
            .find(&late)
            .map(|matched| (matched.start(), matched.end())),
        expected_late,
    );
    assert_eq!(find_regex.find(&absent), None);
    assert!(exists_regex.is_match(&late));
    assert!(!exists_regex.is_match(&absent));
    assert_eq!(cold.change(), Stats::default());
}
