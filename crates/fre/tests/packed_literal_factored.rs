#![forbid(unsafe_code)]

use std::{alloc::System, hint::black_box};

use fre::{BuildError, PlanKind, PortableBuilder, SearchAccounting, SearchError, SearchLimits};
use fre_kernels::PackedLiteralSetError;
use stats_alloc::{INSTRUMENTED_SYSTEM, Region, Stats, StatsAlloc};

#[global_allocator]
static GLOBAL: &StatsAlloc<System> = &INSTRUMENTED_SYSTEM;

fn fixed_width_alternation(count: usize, width: usize) -> String {
    assert!((3..=4).contains(&width));
    let words = (0..count)
        .map(|index| match width {
            3 => format!("{index:03x}"),
            4 => format!("p{index:03x}"),
            _ => unreachable!(),
        })
        .collect::<Vec<_>>();
    format!("(?:{})", words.join("|"))
}

fn cartesian_alternation(columns: &[&[u8]]) -> String {
    let mut words = vec![String::new()];
    for column in columns {
        let mut next = Vec::with_capacity(words.len().saturating_mul(column.len()));
        for prefix in &words {
            for &byte in *column {
                assert!(byte.is_ascii());
                let mut word = prefix.clone();
                word.push(char::from(byte));
                next.push(word);
            }
        }
        words = next;
    }
    format!("(?:{})", words.join("|"))
}

fn build(pattern: &str) -> fre::PortableRegex {
    PortableBuilder::new(pattern)
        .unicode(false)
        .build()
        .unwrap_or_else(|error| panic!("pattern={pattern:?}: {error}"))
}

fn is_factored(regex: &fre::PortableRegex) -> bool {
    let (_, accounting) = regex
        .find_accounted(b"a factored accounting probe", SearchLimits::unlimited())
        .unwrap();
    let SearchAccounting::PackedLiteralSet(accounting) = accounting else {
        panic!("packed plan reported another search family")
    };
    accounting.factored_columns
}

#[test]
fn planner_requires_a_complete_column_proof_above_the_teddy_boundary() {
    let at_native_limit = build(&fixed_width_alternation(64, 4));
    if at_native_limit.build_report().plan == PlanKind::PackedLiteralSet {
        assert!(!is_factored(&at_native_limit));
    }

    for count in [65, 72, 127] {
        let incomplete = build(&fixed_width_alternation(count, 4));
        assert_eq!(
            incomplete.build_report().plan,
            PlanKind::LiteralSetDfa,
            "{count} correlated four-byte alternatives"
        );
    }
    let factored_65_source = cartesian_alternation(&[b"abcde", b"ABCDEFGHIJKLM", b"Q", b"x"]);
    let factored_65 = build(&factored_65_source);
    assert_eq!(factored_65.build_report().plan, PlanKind::PackedLiteralSet);
    assert!(is_factored(&factored_65));

    let factored_128 = build(&fixed_width_alternation(128, 4));
    assert_eq!(factored_128.build_report().plan, PlanKind::PackedLiteralSet);
    assert!(is_factored(&factored_128));

    let above_split_limit = build(&fixed_width_alternation(129, 4));
    assert_eq!(
        above_split_limit.build_report().plan,
        PlanKind::LiteralSetDfa
    );

    let shallow_filter = build(&fixed_width_alternation(65, 3));
    assert_eq!(shallow_filter.build_report().plan, PlanKind::LiteralSetDfa);

    let cartesian_source = cartesian_alternation(&[b"abcdef", b"012345", b"Q", b"xy"]);
    let cartesian = build(&cartesian_source);
    assert_eq!(cartesian.build_report().plan, PlanKind::PackedLiteralSet);
    assert!(is_factored(&cartesian));
}

#[test]
fn factored_route_matches_rust_regex_on_hits_misses_and_malformed_bytes() {
    let source = cartesian_alternation(&[b"mnopqr", b"345678", b"T", b"uv"]);
    let fre = build(&source);
    assert_eq!(fre.build_report().plan, PlanKind::PackedLiteralSet);
    assert!(is_factored(&fre));
    let oracle = regex::bytes::RegexBuilder::new(&source)
        .unicode(false)
        .build()
        .unwrap();

    for haystack in [
        b"".as_slice(),
        b"definite miss",
        b"xxm3Tu--",
        b"r8Tv--m3Tu",
        b"l3Tu m2Tu m3Su m3Tw",
        b"\xFF--m3Tu--\x80",
        b"m3Tu--r8Tv",
    ] {
        let expected = oracle
            .find(haystack)
            .map(|matched| (matched.start(), matched.end()));
        let (actual, _) = fre
            .find_accounted(haystack, SearchLimits::unlimited())
            .unwrap();
        assert_eq!(
            actual.map(|matched| (matched.start(), matched.end())),
            expected,
            "haystack={haystack:?}"
        );
        assert_eq!(
            fre.is_match_accounted(haystack, SearchLimits::unlimited())
                .unwrap()
                .0,
            expected.is_some()
        );
        assert_eq!(
            fre.selected_end(haystack, SearchLimits::unlimited())
                .unwrap()
                .0,
            expected.map(|(_, end)| end)
        );
    }
}

#[test]
fn factored_route_has_exact_persistent_and_search_work_boundaries() {
    let source = cartesian_alternation(&[b"mnopqr", b"345678", b"T", b"uv"]);
    let probe = build(&source);
    assert_eq!(probe.build_report().plan, PlanKind::PackedLiteralSet);
    assert!(is_factored(&probe));
    let persistent = probe.build_report().charged_persistent_bytes;

    let exact = PortableBuilder::new(&source)
        .unicode(false)
        .max_persistent_bytes(persistent)
        .build()
        .unwrap();
    assert_eq!(exact.build_report().charged_persistent_bytes, persistent);
    assert!(matches!(
        PortableBuilder::new(&source)
            .unicode(false)
            .max_persistent_bytes(persistent - 1)
            .build(),
        Err(BuildError::PersistentBytesLimit { needed, limit })
            if needed == persistent && limit == persistent - 1
    ));

    let haystack = b"a long miss exercises the retained factored column owner";
    let (_, accounting) = exact
        .find_accounted(haystack, SearchLimits::unlimited())
        .unwrap();
    let SearchAccounting::PackedLiteralSet(accounting) = accounting else {
        panic!("factored route reported another search family")
    };
    assert!(accounting.factored_columns);
    let work = u64::try_from(accounting.work_upper_bound).unwrap();
    let exact_work = SearchLimits {
        max_work: work,
        max_scratch_bytes: 0,
    };
    exact.find_accounted(haystack, exact_work).unwrap();
    let one_below = SearchLimits {
        max_work: work - 1,
        max_scratch_bytes: 0,
    };
    assert!(matches!(
        exact.find_accounted(haystack, one_below),
        Err(SearchError::PackedLiteralSet(PackedLiteralSetError::WorkLimit {
            needed,
            limit
        })) if needed == accounting.work_upper_bound
            && limit == accounting.work_upper_bound - 1
    ));
}

#[test]
fn factored_route_has_zero_steady_allocations() {
    let source = cartesian_alternation(&[b"abcdef", b"012345", b"Q", b"xy"]);
    let regex = build(&source);
    assert_eq!(regex.build_report().plan, PlanKind::PackedLiteralSet);
    assert!(is_factored(&regex));
    let mut haystack = vec![b'!'; 8_192];
    haystack[8_184..8_188].copy_from_slice(b"f5Qy");
    let expected = regex
        .find_accounted(&haystack, SearchLimits::unlimited())
        .unwrap()
        .0;

    let region = Region::new(GLOBAL);
    for _ in 0..32 {
        assert_eq!(
            black_box(
                regex
                    .find_accounted(&haystack, SearchLimits::unlimited())
                    .unwrap()
                    .0,
            ),
            expected
        );
        assert!(
            regex
                .is_match_accounted(&haystack, SearchLimits::unlimited())
                .unwrap()
                .0
        );
    }
    assert_eq!(region.change(), Stats::default());
}
