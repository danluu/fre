#![forbid(unsafe_code)]

use std::{alloc::System, sync::Mutex};

use fre::{
    UnicodeFoldedLiteralBuildAttempt, UnicodeFoldedLiteralBuildError,
    UnicodeFoldedLiteralBuildLimits, UnicodeFoldedLiteralBuilder,
    UnicodeFoldedLiteralIneligibility, UnicodeFoldedLiteralRunError, UnicodeFoldedLiteralRunLimits,
};
use regex::bytes::RegexBuilder;
use stats_alloc::{INSTRUMENTED_SYSTEM, Region, Stats, StatsAlloc};

#[global_allocator]
static GLOBAL: &StatsAlloc<System> = &INSTRUMENTED_SYSTEM;
static TEST_LOCK: Mutex<()> = Mutex::new(());

fn oracle(pattern: &str) -> regex::bytes::Regex {
    let mut builder = RegexBuilder::new(pattern);
    builder
        .unicode(true)
        .case_insensitive(true)
        .build()
        .unwrap()
}

#[test]
fn russian_literal_selects_common_continuation_anchor_and_matches_reference() {
    let _guard = TEST_LOCK.lock().unwrap();
    let pattern = "Шерлок Холмс";
    let count = match UnicodeFoldedLiteralBuilder::new(pattern)
        .case_insensitive(true)
        .build_count()
        .unwrap()
    {
        UnicodeFoldedLiteralBuildAttempt::Admitted(regex) => regex,
        other @ UnicodeFoldedLiteralBuildAttempt::Ineligible { .. } => {
            panic!("unexpected folded-literal attempt: {other:?}")
        }
    };
    assert_eq!(
        count.build_report().planner.cartesian_sequences_saturated,
        6_912
    );
    let span_sum = match UnicodeFoldedLiteralBuilder::new(pattern)
        .case_insensitive(true)
        .build_span_sum()
        .unwrap()
    {
        UnicodeFoldedLiteralBuildAttempt::Admitted(regex) => regex,
        other @ UnicodeFoldedLiteralBuildAttempt::Ineligible { .. } => {
            panic!("unexpected folded-literal attempt: {other:?}")
        }
    };
    assert_eq!(count.build_report().trie.root_prefilter_offset, Some(1));
    assert_eq!(count.build_report().trie.root_prefilter_needles, 2);
    let haystack =
        b"\xffSHERLOCK \xd0\xa8\xd0\xb5\xd1\x80\xd0\xbb\xd0\xbe\xd0\xba \xd0\xa5\xd0\xbe\xd0\xbb\xd0\xbc\xd1\x81; \
          \xd1\x88\xd0\x95\xd0\xa0\xd0\x9b\xd0\x9e\xd0\x9a \xd1\x85\xd0\x9e\xd0\x9b\xd0\x9c\xd0\xa1";
    let expected = oracle(pattern).find_iter(haystack).collect::<Vec<_>>();
    let count_result = count
        .execute(haystack, UnicodeFoldedLiteralRunLimits::unlimited())
        .unwrap();
    let span_result = span_sum
        .execute(haystack, UnicodeFoldedLiteralRunLimits::unlimited())
        .unwrap();
    assert_eq!(count_result.value, u64::try_from(expected.len()).unwrap());
    assert_eq!(
        span_result.value,
        expected
            .iter()
            .map(|matched| u64::try_from(matched.len()).unwrap())
            .sum::<u64>()
    );
    assert_eq!(count_result.receipt.scratch_bytes, 0);
    assert_eq!(span_result.receipt.scratch_bytes, 0);
}

#[test]
fn ordered_russian_alternatives_share_one_prefilter_and_match_reference() {
    let _guard = TEST_LOCK.lock().unwrap();
    let pattern = "Шерлок Холмс|Джон Уотсон|Ирен Адлер|инспектор Лестрейд|профессор Мориарти";
    let count = match UnicodeFoldedLiteralBuilder::new(pattern)
        .case_insensitive(true)
        .build_count()
        .unwrap()
    {
        UnicodeFoldedLiteralBuildAttempt::Admitted(regex) => regex,
        other @ UnicodeFoldedLiteralBuildAttempt::Ineligible { .. } => {
            panic!("unexpected folded-literal attempt: {other:?}")
        }
    };
    let span_sum = match UnicodeFoldedLiteralBuilder::new(pattern)
        .case_insensitive(true)
        .build_span_sum()
        .unwrap()
    {
        UnicodeFoldedLiteralBuildAttempt::Admitted(regex) => regex,
        other @ UnicodeFoldedLiteralBuildAttempt::Ineligible { .. } => {
            panic!("unexpected folded-literal attempt: {other:?}")
        }
    };
    assert_eq!(count.build_report().planner.patterns, 5);
    assert_eq!(count.build_report().trie.patterns, 5);
    assert!(count.build_report().trie.root_prefilter_needles > 0);
    let mut haystack = vec![0xFF, 0x80];
    haystack.extend_from_slice(
        "ШЕРЛОК ХОЛМС/джон уотсон/ИРЕН АДЛЕР/инспектор лестрейд/ПРОФЕССОР МОРИАРТИ".as_bytes(),
    );
    haystack.extend_from_slice(&[0xF4, 0x90, 0x80, 0x80]);
    let expected = oracle(pattern).find_iter(&haystack).collect::<Vec<_>>();
    assert_eq!(
        count
            .execute(&haystack, UnicodeFoldedLiteralRunLimits::unlimited())
            .unwrap()
            .value,
        u64::try_from(expected.len()).unwrap()
    );
    assert_eq!(
        span_sum
            .execute(&haystack, UnicodeFoldedLiteralRunLimits::unlimited())
            .unwrap()
            .value,
        expected
            .iter()
            .map(|matched| u64::try_from(matched.len()).unwrap())
            .sum::<u64>()
    );
}

#[test]
fn ordered_alternative_priority_beats_shorter_end_at_the_same_start() {
    let _guard = TEST_LOCK.lock().unwrap();
    for pattern in ["ΣX|ς", "ς|ΣX"] {
        let count = match UnicodeFoldedLiteralBuilder::new(pattern)
            .case_insensitive(true)
            .build_count()
            .unwrap()
        {
            UnicodeFoldedLiteralBuildAttempt::Admitted(regex) => regex,
            other @ UnicodeFoldedLiteralBuildAttempt::Ineligible { .. } => {
                panic!("unexpected folded-literal attempt for {pattern:?}: {other:?}")
            }
        };
        let span_sum = match UnicodeFoldedLiteralBuilder::new(pattern)
            .case_insensitive(true)
            .build_span_sum()
            .unwrap()
        {
            UnicodeFoldedLiteralBuildAttempt::Admitted(regex) => regex,
            other @ UnicodeFoldedLiteralBuildAttempt::Ineligible { .. } => {
                panic!("unexpected folded-literal attempt for {pattern:?}: {other:?}")
            }
        };
        let haystack = "σxσx".as_bytes();
        let expected = oracle(pattern).find_iter(haystack).collect::<Vec<_>>();
        assert_eq!(
            count
                .execute(haystack, UnicodeFoldedLiteralRunLimits::unlimited())
                .unwrap()
                .value,
            u64::try_from(expected.len()).unwrap()
        );
        assert_eq!(
            span_sum
                .execute(haystack, UnicodeFoldedLiteralRunLimits::unlimited())
                .unwrap()
                .value,
            expected
                .iter()
                .map(|matched| u64::try_from(matched.len()).unwrap())
                .sum::<u64>()
        );
    }
}

#[test]
fn arbitrary_bytes_match_regex_bytes_reference() {
    let _guard = TEST_LOCK.lock().unwrap();
    let pattern = "Ше";
    let count = match UnicodeFoldedLiteralBuilder::new(pattern)
        .case_insensitive(true)
        .build_count()
        .unwrap()
    {
        UnicodeFoldedLiteralBuildAttempt::Admitted(regex) => regex,
        other @ UnicodeFoldedLiteralBuildAttempt::Ineligible { .. } => {
            panic!("unexpected folded-literal attempt: {other:?}")
        }
    };
    let span_sum = match UnicodeFoldedLiteralBuilder::new(pattern)
        .case_insensitive(true)
        .build_span_sum()
        .unwrap()
    {
        UnicodeFoldedLiteralBuildAttempt::Admitted(regex) => regex,
        other @ UnicodeFoldedLiteralBuildAttempt::Ineligible { .. } => {
            panic!("unexpected folded-literal attempt: {other:?}")
        }
    };
    let reference = oracle(pattern);
    let mut state = 0x9E37_79B9_7F4A_7C15_u64;
    for length in 0..=96 {
        for _ in 0..128 {
            let mut haystack = Vec::with_capacity(length);
            for _ in 0..length {
                state ^= state << 7;
                state ^= state >> 9;
                state ^= state << 8;
                haystack.push(state.to_le_bytes()[0]);
            }
            if length >= 4 && state.trailing_zeros() >= 2 {
                let at = usize::from(state.to_le_bytes()[1]) % (length - 3);
                haystack[at..at + 4].copy_from_slice("Ше".as_bytes());
            }
            let expected = reference.find_iter(&haystack).collect::<Vec<_>>();
            let count_result = count
                .execute(&haystack, UnicodeFoldedLiteralRunLimits::unlimited())
                .unwrap();
            let span_result = span_sum
                .execute(&haystack, UnicodeFoldedLiteralRunLimits::unlimited())
                .unwrap();
            assert_eq!(
                count_result.value,
                u64::try_from(expected.len()).unwrap(),
                "{haystack:?}"
            );
            assert_eq!(
                span_result.value,
                expected
                    .iter()
                    .map(|matched| u64::try_from(matched.len()).unwrap())
                    .sum::<u64>(),
                "{haystack:?}"
            );
        }
    }
}

#[test]
fn adjacent_overlapping_candidates_reduce_like_find_iter() {
    let _guard = TEST_LOCK.lock().unwrap();
    let pattern = "ШШ";
    let count = match UnicodeFoldedLiteralBuilder::new(pattern)
        .case_insensitive(true)
        .build_count()
        .unwrap()
    {
        UnicodeFoldedLiteralBuildAttempt::Admitted(regex) => regex,
        other @ UnicodeFoldedLiteralBuildAttempt::Ineligible { .. } => {
            panic!("unexpected folded-literal attempt: {other:?}")
        }
    };
    let span_sum = match UnicodeFoldedLiteralBuilder::new(pattern)
        .case_insensitive(true)
        .build_span_sum()
        .unwrap()
    {
        UnicodeFoldedLiteralBuildAttempt::Admitted(regex) => regex,
        other @ UnicodeFoldedLiteralBuildAttempt::Ineligible { .. } => {
            panic!("unexpected folded-literal attempt: {other:?}")
        }
    };
    for haystack in [
        "ШШШ".as_bytes(),
        "шШшШ".as_bytes(),
        b"\x88\xd0\xa8\xd0\xa8\xd0\xa8\xff".as_slice(),
    ] {
        let expected = oracle(pattern).find_iter(haystack).collect::<Vec<_>>();
        assert_eq!(
            count
                .execute(haystack, UnicodeFoldedLiteralRunLimits::unlimited())
                .unwrap()
                .value,
            u64::try_from(expected.len()).unwrap()
        );
        assert_eq!(
            span_sum
                .execute(haystack, UnicodeFoldedLiteralRunLimits::unlimited())
                .unwrap()
                .value,
            expected
                .iter()
                .map(|matched| u64::try_from(matched.len()).unwrap())
                .sum::<u64>()
        );
    }
}

#[test]
fn structural_misses_wide_prefilters_and_resource_failures_are_distinct() {
    let _guard = TEST_LOCK.lock().unwrap();
    assert!(matches!(
        UnicodeFoldedLiteralBuilder::new("abc")
            .case_insensitive(true)
            .build_count()
            .unwrap(),
        UnicodeFoldedLiteralBuildAttempt::Ineligible {
            reason: UnicodeFoldedLiteralIneligibility::RootIsNotNonAsciiFoldClass,
            ..
        }
    ));
    assert!(matches!(
        UnicodeFoldedLiteralBuilder::new("Ш+")
            .case_insensitive(true)
            .build_count()
            .unwrap(),
        UnicodeFoldedLiteralBuildAttempt::Ineligible {
            reason: UnicodeFoldedLiteralIneligibility::UnsupportedHir,
            ..
        }
    ));
    let wide = match UnicodeFoldedLiteralBuilder::new("\u{0345}")
        .case_insensitive(true)
        .build_count()
        .unwrap()
    {
        UnicodeFoldedLiteralBuildAttempt::Admitted(regex) => regex,
        other @ UnicodeFoldedLiteralBuildAttempt::Ineligible { .. } => {
            panic!("wide byte-set prefilter unexpectedly ineligible: {other:?}")
        }
    };
    assert!(wide.build_report().trie.root_prefilter_needles > 3);
    assert!(matches!(
        UnicodeFoldedLiteralBuilder::new("Ше")
            .case_insensitive(true)
            .limits(UnicodeFoldedLiteralBuildLimits {
                max_scalar_positions: 1,
                ..UnicodeFoldedLiteralBuildLimits::default()
            })
            .build_count(),
        Err(UnicodeFoldedLiteralBuildError::Resource {
            resource: "scalar positions",
            needed: 2,
            limit: 1,
        })
    ));
}

#[test]
fn exact_run_limits_admit_and_every_facade_dimension_refuses_one_below() {
    let _guard = TEST_LOCK.lock().unwrap();
    let regex = match UnicodeFoldedLiteralBuilder::new("Ше")
        .case_insensitive(true)
        .build_count()
        .unwrap()
    {
        UnicodeFoldedLiteralBuildAttempt::Admitted(regex) => regex,
        other @ UnicodeFoldedLiteralBuildAttempt::Ineligible { .. } => {
            panic!("unexpected folded-literal attempt: {other:?}")
        }
    };
    let haystack = b"xx\xd0\xa8\xd0\xb5yy\xd1\x88\xd0\xb5";
    let upper = regex.full_window_upper_bounds(haystack.len()).unwrap();
    let exact = UnicodeFoldedLiteralRunLimits::exact(upper);
    assert_eq!(regex.execute(haystack, exact).unwrap().value, 2);
    for limits in [
        UnicodeFoldedLiteralRunLimits {
            max_reducer_steps: upper.reducer_steps - 1,
            ..UnicodeFoldedLiteralRunLimits::unlimited()
        },
        UnicodeFoldedLiteralRunLimits {
            max_count: upper.count - 1,
            ..UnicodeFoldedLiteralRunLimits::unlimited()
        },
        UnicodeFoldedLiteralRunLimits {
            max_work: upper.work - 1,
            ..UnicodeFoldedLiteralRunLimits::unlimited()
        },
    ] {
        assert!(matches!(
            regex.execute(haystack, limits),
            Err(UnicodeFoldedLiteralRunError::Resource { .. })
        ));
    }
    let scan_one_below = UnicodeFoldedLiteralRunLimits {
        scan: fre::FoldedLiteralTrieScanLimits {
            max_source_byte_reads: upper.scan.source_byte_reads - 1,
            ..fre::FoldedLiteralTrieScanLimits::unlimited()
        },
        ..UnicodeFoldedLiteralRunLimits::unlimited()
    };
    assert!(matches!(
        regex.execute(haystack, scan_one_below),
        Err(UnicodeFoldedLiteralRunError::Scan(_))
    ));
}

#[test]
fn repeated_operations_allocate_nothing() {
    let _guard = TEST_LOCK.lock().unwrap();
    let regex = match UnicodeFoldedLiteralBuilder::new("Шерлок Холмс")
        .case_insensitive(true)
        .build_count()
        .unwrap()
    {
        UnicodeFoldedLiteralBuildAttempt::Admitted(regex) => regex,
        other @ UnicodeFoldedLiteralBuildAttempt::Ineligible { .. } => {
            panic!("unexpected folded-literal attempt: {other:?}")
        }
    };
    let haystack = "Шерлок Холмс; шерлок холмс".as_bytes();
    let limits = UnicodeFoldedLiteralRunLimits::exact(
        regex.full_window_upper_bounds(haystack.len()).unwrap(),
    );
    let region = Region::new(GLOBAL);
    for _ in 0..32 {
        assert_eq!(regex.execute(haystack, limits).unwrap().value, 2);
    }
    assert_eq!(region.change(), Stats::default());
}
