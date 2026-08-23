#![forbid(unsafe_code)]

use std::{alloc::System, sync::Mutex};

use fre::{
    FoldedLiteralTrieScanError, PlanKind, PlanSelection, PortableBuilder, PortableFindIterLimits,
    PortableRegex, SearchAccounting, SearchError, SearchLimits, SearchWindow,
    UNICODE_FOLDED_LITERAL_SEARCH_ALGORITHM_ID,
};
use regex::bytes::{Regex, RegexBuilder};
use stats_alloc::{INSTRUMENTED_SYSTEM, Region, Stats, StatsAlloc};

#[global_allocator]
static GLOBAL: &StatsAlloc<System> = &INSTRUMENTED_SYSTEM;
static TEST_LOCK: Mutex<()> = Mutex::new(());

const RUSSIAN: &str = "Шерлок Холмс";
const LONG_FIRST: &str = "ΣABCDEFGHIJKL|ς";
const SHORT_FIRST: &str = "ς|ΣABCDEFGHIJKL";
const DUPLICATE_PREFIX: &str = "ΣABCDEFGHIJKL|ς|ΣABCDEFGHIJKL|σ";

fn oracle(pattern: &str) -> Regex {
    let mut builder = RegexBuilder::new(pattern);
    builder
        .unicode(true)
        .case_insensitive(true)
        .build()
        .unwrap()
}

fn auto_regex(pattern: &str) -> PortableRegex {
    PortableBuilder::new(pattern)
        .unicode(true)
        .case_insensitive(true)
        .build()
        .unwrap()
}

fn forced_k0(pattern: &str) -> PortableRegex {
    PortableBuilder::new(pattern)
        .unicode(true)
        .case_insensitive(true)
        .plan_selection(PlanSelection::ForceK0)
        .build()
        .unwrap()
}

fn span(matched: Option<fre::Match>) -> Option<(usize, usize)> {
    matched.map(|matched| (matched.start(), matched.end()))
}

fn oracle_window(
    regex: &Regex,
    haystack: &[u8],
    start: usize,
    end: usize,
) -> Option<(usize, usize)> {
    regex.find(&haystack[start..end]).map(|matched| {
        (
            start.checked_add(matched.start()).unwrap(),
            start.checked_add(matched.end()).unwrap(),
        )
    })
}

#[test]
fn auto_route_is_honest_and_force_k0_and_finite_incumbents_win() {
    let _guard = TEST_LOCK.lock().unwrap();
    let automatic = auto_regex(RUSSIAN);
    assert_eq!(
        automatic.build_report().plan,
        PlanKind::UnicodeFoldedLiteral
    );
    assert_eq!(
        automatic.runtime_implementation_id(),
        UNICODE_FOLDED_LITERAL_SEARCH_ALGORITHM_ID
    );
    let build = automatic
        .unicode_folded_literal_build_accounting()
        .expect("folded plan publishes its construction census");
    assert_eq!(build.planner.patterns, 1);
    assert!(build.planner.cartesian_sequences_saturated > 4_096);
    assert!(
        automatic.build_report().planner_work > u64::try_from(build.planner.work).unwrap(),
        "the generic report must retain incumbent-gate work before folded construction"
    );
    assert_eq!(build.trie.states, automatic.build_report().states);
    assert_eq!(build.trie.transitions, automatic.build_report().edges);
    assert_eq!(build.facade_owner_allocations, 1);
    assert_eq!(
        build.persistent_allocations,
        build.trie.allocations.checked_add(1).unwrap()
    );
    assert_eq!(
        build.persistent_bytes,
        automatic.build_report().plan_storage_bytes
    );
    assert_eq!(
        build.persistent_bytes,
        build
            .trie
            .persistent_bytes
            .checked_add(build.facade_owner_persistent_bytes)
            .unwrap()
    );

    let forced = forced_k0(RUSSIAN);
    assert_eq!(forced.build_report().plan, PlanKind::K0);
    assert!(forced.unicode_folded_literal_build_accounting().is_none());
    assert_eq!(forced.runtime_implementation_id(), "k0");

    let finite = auto_regex("Ше");
    assert_ne!(finite.build_report().plan, PlanKind::UnicodeFoldedLiteral);
    assert!(matches!(
        finite.build_report().plan,
        PlanKind::PackedLiteralSet | PlanKind::LiteralSetDfa
    ));
    assert!(finite.unicode_folded_literal_build_accounting().is_none());
}

#[test]
fn ordered_alternation_priority_and_shortest_end_match_regex_bytes() {
    let _guard = TEST_LOCK.lock().unwrap();
    let haystack = "xxσabcdefghijklYY".as_bytes();
    for pattern in [LONG_FIRST, SHORT_FIRST] {
        let expected = oracle(pattern);
        let automatic = auto_regex(pattern);
        let forced = forced_k0(pattern);
        assert_eq!(
            automatic.build_report().plan,
            PlanKind::UnicodeFoldedLiteral
        );

        let expected_find = expected
            .find(haystack)
            .map(|matched| (matched.start(), matched.end()));
        let expected_shortest = expected.shortest_match(haystack);
        let (automatic_find, accounting) =
            automatic
                .find_accounted(haystack, SearchLimits::unlimited())
                .unwrap();
        assert_eq!(span(automatic_find), expected_find, "{pattern}");
        assert!(matches!(
            accounting,
            SearchAccounting::UnicodeFoldedLiteral(_)
        ));
        let (exists, exists_accounting) = automatic
            .is_match_accounted(haystack, SearchLimits::unlimited())
            .unwrap();
        assert!(exists);
        let SearchAccounting::UnicodeFoldedLiteral(exists_actual) = exists_accounting else {
            panic!("existence lost folded accounting for {pattern}");
        };
        assert_eq!(exists_actual.candidate_events, 1);
        assert_eq!(
            span(
                forced
                    .find_accounted(haystack, SearchLimits::unlimited())
                    .unwrap()
                    .0,
            ),
            expected_find,
            "forced K0 {pattern}"
        );
        assert_eq!(
            automatic
                .shortest_match(haystack, SearchLimits::unlimited())
                .unwrap()
                .0,
            expected_shortest,
            "shortest {pattern}"
        );
    }

    let long = auto_regex(LONG_FIRST)
        .find_accounted(haystack, SearchLimits::unlimited())
        .unwrap()
        .0
        .unwrap();
    let short = auto_regex(SHORT_FIRST)
        .find_accounted(haystack, SearchLimits::unlimited())
        .unwrap()
        .0
        .unwrap();
    assert!(long.end() > short.end());
    assert_eq!(long.start(), short.start());

    let duplicates = auto_regex(DUPLICATE_PREFIX);
    let duplicate_build = duplicates
        .unicode_folded_literal_build_accounting()
        .expect("duplicate alternatives retain the folded plan");
    assert_eq!(duplicate_build.planner.patterns, 4);
    assert_eq!(
        span(
            duplicates
                .find_accounted(haystack, SearchLimits::unlimited())
                .unwrap()
                .0
        ),
        oracle(DUPLICATE_PREFIX)
            .find(haystack)
            .map(|matched| (matched.start(), matched.end()))
    );
    assert_eq!(
        span(
            forced_k0(DUPLICATE_PREFIX)
                .find_accounted(haystack, SearchLimits::unlimited())
                .unwrap()
                .0
        ),
        oracle(DUPLICATE_PREFIX)
            .find(haystack)
            .map(|matched| (matched.start(), matched.end()))
    );
}

#[test]
fn arbitrary_bytes_windows_and_iteration_match_oracle_and_force_k0() {
    let _guard = TEST_LOCK.lock().unwrap();
    let expected = oracle(RUSSIAN);
    let automatic = auto_regex(RUSSIAN);
    let forced = forced_k0(RUSSIAN);
    let mut haystack = vec![0xFF, 0x80, b'x'];
    haystack.extend_from_slice("ШЕРЛОК ХОЛМС".as_bytes());
    haystack.extend_from_slice(&[0xF4, 0x90, 0x80, 0x80, b'/']);
    haystack.extend_from_slice("шерлок холмс".as_bytes());
    haystack.extend_from_slice(&[0xC0, 0xAF, b'z']);

    let mut windows = vec![
        (0, 0),
        (0, haystack.len()),
        (1, haystack.len()),
        (3, haystack.len()),
        (3, 3),
        (4, haystack.len().saturating_sub(1)),
        (haystack.len(), haystack.len()),
    ];
    let mut state = 0xD1B5_4A32_D192_ED03_u64;
    for _ in 0..96 {
        state = state
            .wrapping_mul(6_364_136_223_846_793_005)
            .wrapping_add(1_442_695_040_888_963_407);
        let first = usize::try_from(state).unwrap() % (haystack.len() + 1);
        state ^= state.rotate_left(17);
        let second = usize::try_from(state).unwrap() % (haystack.len() + 1);
        windows.push((first.min(second), first.max(second)));
    }

    for (start, end) in windows {
        let expected_find = oracle_window(&expected, &haystack, start, end);
        let expected_shortest = expected
            .shortest_match(&haystack[start..end])
            .map(|offset| start.checked_add(offset).unwrap());
        for (name, regex) in [("automatic", &automatic), ("forced K0", &forced)] {
            let (found, _) = regex
                .find_window(
                    &haystack,
                    SearchWindow::new(start, end),
                    SearchLimits::unlimited(),
                )
                .unwrap();
            assert_eq!(span(found), expected_find, "{name}, window {start}..{end}");
            assert_eq!(
                span(
                    regex
                        .find_window_value(
                            &haystack,
                            SearchWindow::new(start, end),
                            SearchLimits::unlimited(),
                        )
                        .unwrap()
                ),
                expected_find,
                "{name}, value window {start}..{end}"
            );
            assert_eq!(
                regex
                    .is_match_window(
                        &haystack,
                        SearchWindow::new(start, end),
                        SearchLimits::unlimited(),
                    )
                    .unwrap()
                    .0,
                expected_find.is_some(),
                "{name}, existence window {start}..{end}"
            );
            assert_eq!(
                regex
                    .is_match_window_value(
                        &haystack,
                        SearchWindow::new(start, end),
                        SearchLimits::unlimited(),
                    )
                    .unwrap(),
                expected_find.is_some(),
                "{name}, value existence window {start}..{end}"
            );
            assert_eq!(
                regex
                    .shortest_match_at(&haystack[..end], start, SearchLimits::unlimited())
                    .unwrap()
                    .0,
                expected_shortest,
                "{name}, shortest window {start}..{end}"
            );
        }
    }

    let expected_matches = expected
        .find_iter(&haystack)
        .map(|matched| (matched.start(), matched.end()))
        .collect::<Vec<_>>();
    for (name, regex) in [("automatic", &automatic), ("forced K0", &forced)] {
        let matches = regex
            .find_iter(&haystack, PortableFindIterLimits::unlimited())
            .unwrap()
            .map(|item| {
                let matched = item.unwrap();
                (matched.start(), matched.end())
            })
            .collect::<Vec<_>>();
        assert_eq!(matches, expected_matches, "{name} iteration");
    }

    for invalid in [
        SearchWindow::new(2, 1),
        SearchWindow::new(0, haystack.len() + 1),
    ] {
        assert_eq!(
            automatic
                .find_window_value(&haystack, invalid, SearchLimits::unlimited())
                .unwrap_err(),
            automatic
                .find_window(&haystack, invalid, SearchLimits::unlimited())
                .unwrap_err()
        );
        assert_eq!(
            automatic
                .is_match_window_value(&haystack, invalid, SearchLimits::unlimited())
                .unwrap_err(),
            automatic
                .is_match_window(&haystack, invalid, SearchLimits::unlimited())
                .unwrap_err()
        );
        assert!(
            forced
                .find_window(&haystack, invalid, SearchLimits::unlimited())
                .is_err()
        );
    }
}

#[test]
fn early_stop_actuals_exclude_later_candidates_and_limits_preflight() {
    let _guard = TEST_LOCK.lock().unwrap();
    let regex = auto_regex(RUSSIAN);
    let mut haystack = RUSSIAN.as_bytes().to_vec();
    haystack.extend(std::iter::repeat_n(b'x', 2_048));
    haystack.extend_from_slice(RUSSIAN.as_bytes());
    let upper = regex
        .unicode_folded_literal_search_upper_bounds(haystack.len())
        .unwrap()
        .expect("folded plan publishes a source-independent envelope");

    let (matched, accounting) = regex
        .find_accounted(&haystack, SearchLimits::unlimited())
        .unwrap();
    assert_eq!(span(matched), Some((0, RUSSIAN.len())));
    let charged_work = accounting.work_or_linear_terms();
    let SearchAccounting::UnicodeFoldedLiteral(actual) = accounting else {
        panic!("automatic route returned non-folded accounting");
    };
    assert_eq!(actual.candidate_events, 1);
    assert_eq!(actual.candidate_starts, 1);
    assert!(actual.work < upper.work);
    assert!(actual.source_byte_reads < upper.source_byte_reads);
    assert_eq!(charged_work, u64::try_from(actual.work).unwrap());

    let below = SearchLimits {
        max_work: u64::try_from(upper.work - 1).unwrap(),
        max_scratch_bytes: usize::MAX,
    };
    let error = regex.find_accounted(&haystack, below).unwrap_err();
    let SearchError::UnicodeFoldedLiteral(error) = error else {
        panic!("work refusal lost folded search identity");
    };
    assert!(matches!(
        error.source,
        FoldedLiteralTrieScanError::Resource { .. }
    ));
    assert_eq!(error.actual_work, 0);
    assert_eq!(error.actual_source_byte_reads, 0);
    assert_eq!(
        regex.find_value(&haystack, below).unwrap_err(),
        regex.find_accounted(&haystack, below).unwrap_err()
    );
    assert_eq!(
        regex.is_match_value(&haystack, below).unwrap_err(),
        regex.is_match_accounted(&haystack, below).unwrap_err()
    );
}

#[test]
fn repeated_portable_folded_search_and_iteration_allocate_nothing() {
    let _guard = TEST_LOCK.lock().unwrap();
    let regex = auto_regex(RUSSIAN);
    let haystack = "ШЕРЛОК ХОЛМС; шерлок холмс".as_bytes();
    let region = Region::new(GLOBAL);
    let (first, first_accounting) = regex
        .find_accounted(haystack, SearchLimits::unlimited())
        .unwrap();
    assert_eq!(span(first), Some((0, RUSSIAN.len())));
    for _ in 0..32 {
        assert!(regex.is_match(haystack));
        assert_eq!(span(regex.find(haystack)), span(first));
        assert!(
            regex
                .is_match_value(haystack, SearchLimits::unlimited())
                .unwrap()
        );
        assert_eq!(
            span(
                regex
                    .find_value(haystack, SearchLimits::unlimited())
                    .unwrap()
            ),
            span(first)
        );
        let (found, accounting) = regex
            .find_accounted(haystack, SearchLimits::unlimited())
            .unwrap();
        assert_eq!(span(found), span(first));
        assert_eq!(accounting, first_accounting);
        let mut matches = regex
            .find_iter(haystack, PortableFindIterLimits::unlimited())
            .unwrap();
        let mut count = 0_usize;
        while let Some(item) = matches.next() {
            item.unwrap();
            count += 1;
        }
        assert_eq!(count, 2);
    }
    assert_eq!(region.change(), Stats::default());
}
