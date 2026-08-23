#![forbid(unsafe_code)]

use std::{alloc::System, hint::black_box};

use fre::{BuildLimits, PlanKind, PortableBuilder};
use stats_alloc::{INSTRUMENTED_SYSTEM, Region, Stats, StatsAlloc};

#[global_allocator]
static GLOBAL: &StatsAlloc<System> = &INSTRUMENTED_SYSTEM;

#[test]
fn literal_set_dfa_ordinary_facades_allocate_nothing() {
    let regex = PortableBuilder::new("ab|a|ba")
        .unicode(false)
        .limits(BuildLimits {
            packed_literal_set: fre_kernels::PackedLiteralSetBuildLimits {
                max_patterns: 0,
                ..fre_kernels::PackedLiteralSetBuildLimits::default()
            },
            ..BuildLimits::default()
        })
        .build()
        .expect("literal-set DFA fixture builds");
    assert_eq!(regex.build_report().plan, PlanKind::LiteralSetDfa);
    let early = b"abzzzz";
    let dense = b"abababababababab";
    let malformed = b"\xff\x80zzab\0abab";
    let miss = b"zzzzzzzzzzzz";
    let expected_early = regex.find(early);
    let expected_dense = regex.find(dense);
    let expected_malformed = regex.find(malformed);

    let measured = Region::new(GLOBAL);
    for _ in 0..64 {
        assert!(black_box(regex.is_match(black_box(early))));
        assert_eq!(black_box(regex.find(black_box(early))), expected_early);
        assert!(black_box(regex.is_match(black_box(dense))));
        assert_eq!(black_box(regex.find(black_box(dense))), expected_dense);
        assert!(black_box(regex.is_match(black_box(malformed))));
        assert_eq!(
            black_box(regex.find(black_box(malformed))),
            expected_malformed,
        );
        assert!(!black_box(regex.is_match(black_box(miss))));
        assert_eq!(black_box(regex.find(black_box(miss))), None);
    }
    assert_eq!(measured.change(), Stats::default());
}
