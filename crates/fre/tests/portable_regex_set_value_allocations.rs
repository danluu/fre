#![forbid(unsafe_code)]

use std::alloc::System;

use fre::{PlanKind, PortableRegexSet, PortableRegexSetRunLimits};
use stats_alloc::{INSTRUMENTED_SYSTEM, Region, Stats, StatsAlloc};

#[global_allocator]
static GLOBAL: &StatsAlloc<System> = &INSTRUMENTED_SYSTEM;

#[test]
fn immutable_set_value_existence_grows_once_then_reuses_pooled_scratch() {
    let pattern = "(?:ab|cd|ef)+X";
    let haystack = b"ababX";
    let set = PortableRegexSet::new([pattern]).expect("K0 byte set");
    assert_eq!(
        set.pattern_build_report(0).expect("pattern report").plan,
        PlanKind::K0,
    );
    let cold = Region::new(GLOBAL);
    assert!(
        set.is_match_value_unlimited(haystack)
            .expect("cold value search")
    );
    assert!(cold.change().allocations > 0);
    drop(cold);

    let warm = Region::new(GLOBAL);
    for start in [0, 1, haystack.len()] {
        for _ in 0..16 {
            assert_eq!(
                set.is_match_value_at_unlimited(haystack, start)
                    .expect("warm ranged value search"),
                start < haystack.len(),
            );
        }
    }
    assert_eq!(warm.change(), Stats::default());
}

#[test]
fn fused_exact_literal_full_existence_has_no_execution_allocations() {
    let set = PortableRegexSet::new([
        "alpha",
        "alphabet",
        "alpha",
        r"(?-u:\xFF\x00)",
        "omega",
        "beta",
        "gamma",
        "delta",
    ])
    .expect("fused exact-literal byte set");
    assert!((0..set.len()).all(|index| {
        set.pattern_build_report(index)
            .expect("pattern report")
            .plan
            == PlanKind::ExactLiteral
    }));
    assert!(set.build_report().fused_literal_set_storage_bytes > 0);

    let long_absent = [b'x'; 256];
    let mut long_first = [b'x'; 256];
    long_first[200..205].copy_from_slice(b"alpha");
    let mut long_suffix = [b'x'; 256];
    long_suffix[200..205].copy_from_slice(b"delta");

    let region = Region::new(GLOBAL);
    for haystack in [
        b"no-match".as_slice(),
        b"prefix alphabet suffix".as_slice(),
        b"raw \xFF\x00 bytes".as_slice(),
        long_absent.as_slice(),
        long_first.as_slice(),
        long_suffix.as_slice(),
    ] {
        for _ in 0..32 {
            let _ = set
                .is_match_value_unlimited(haystack)
                .expect("fused full existence");
            let mut flags = [false; 8];
            let _ = set
                .matches_read_at_value(
                    &mut flags,
                    haystack,
                    0,
                    PortableRegexSetRunLimits::unlimited(),
                )
                .expect("fused caller-buffer all-ID value search");
        }
    }
    assert_eq!(region.change(), Stats::default());
}

#[test]
fn fused_exact_literal_all_id_ordinary_constituents_do_not_allocate() {
    let patterns = [
        "literal_00",
        "literal_01",
        "literal_02",
        "literal_03",
        "literal_04",
        "literal_05",
        "literal_06",
        "literal_07",
    ];
    let set = PortableRegexSet::new(patterns).expect("fused exact-literal byte set");
    assert!(set.build_report().fused_literal_set_build.is_some());

    let absent = [b'x'; 256];
    let mut first = absent;
    first[96..106].copy_from_slice(patterns[0].as_bytes());
    let mut suffix = absent;
    suffix[192..202].copy_from_slice(patterns[7].as_bytes());

    let region = Region::new(GLOBAL);
    for (haystack, expected_any, expected_id) in [
        (absent.as_slice(), false, None),
        (first.as_slice(), true, Some(0_usize)),
        (suffix.as_slice(), true, Some(7_usize)),
    ] {
        for _ in 0..32 {
            let mut flags = [false; 10];
            flags[8] = true;
            assert_eq!(
                set.matches_read_at_value(
                    &mut flags,
                    haystack,
                    0,
                    PortableRegexSetRunLimits::unlimited(),
                )
                .expect("fused ordinary caller-buffer all-ID value search"),
                expected_any,
            );
            for (index, &flag) in flags[..patterns.len()].iter().enumerate() {
                assert_eq!(flag, expected_id == Some(index));
            }
            assert!(flags[8]);
            assert!(!flags[9]);
        }
    }
    assert_eq!(region.change(), Stats::default());
}

#[test]
fn ineligible_exact_literal_existence_and_empty_fallback_do_not_allocate() {
    let positive = PortableRegexSet::new(["ab", "bc"]).expect("two positive literals");
    let nullable = PortableRegexSet::new(["", "bc"]).expect("empty-literal fallback set");
    assert_eq!(positive.build_report().fused_literal_set_build, None);
    assert_eq!(nullable.build_report().fused_literal_set_build, None);
    let haystack = b"__ab__bc";

    let region = Region::new(GLOBAL);
    for set in [&positive, &nullable] {
        for start in [0, 3, haystack.len()] {
            for _ in 0..32 {
                let _ = set
                    .is_match_value_at_unlimited(haystack, start)
                    .expect("ineligible ranged exact-literal value search");
                let mut flags = [false; 2];
                let _ = set
                    .matches_read_at_value(
                        &mut flags,
                        haystack,
                        start,
                        PortableRegexSetRunLimits::unlimited(),
                    )
                    .expect("ineligible caller-buffer exact-literal value search");
            }
        }
    }
    assert_eq!(region.change(), Stats::default());
}
