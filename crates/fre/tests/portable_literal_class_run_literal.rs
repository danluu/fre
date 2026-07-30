#![allow(
    clippy::arithmetic_side_effects,
    reason = "exhaustive generators are bounded to small test inputs"
)]

use fre::{
    BuildError, BuildLimits, LiteralClassRunLiteralBuildLimits, LiteralClassRunLiteralSearchError,
    PlanKind, PortableBuilder, PortableFindIterLimits, SearchAccounting, SearchError, SearchLimits,
    SearchSessionLimits, SearchWindow,
};
use regex::bytes::RegexBuilder;
use regex_automata::{Input, meta::Regex as MetaRegex, util::syntax};

fn portable(pattern: &str) -> fre::PortableRegex {
    PortableBuilder::new(pattern)
        .unicode(false)
        .build()
        .unwrap_or_else(|error| panic!("portable build failed for {pattern:?}: {error}"))
}

fn oracle(pattern: &str) -> MetaRegex {
    MetaRegex::builder()
        .configure(MetaRegex::config().utf8_empty(false))
        .syntax(syntax::Config::new().utf8(false).unicode(false))
        .build(pattern)
        .unwrap_or_else(|error| panic!("oracle build failed for {pattern:?}: {error}"))
}

fn byte_strings(maximum_length: usize, alphabet: &[u8]) -> Vec<Vec<u8>> {
    let mut all = vec![Vec::new()];
    let mut frontier = vec![Vec::new()];
    for _ in 0..maximum_length {
        let mut next = Vec::new();
        for prefix in &frontier {
            for &byte in alphabet {
                let mut value = prefix.clone();
                value.push(byte);
                all.push(value.clone());
                next.push(value);
            }
        }
        frontier = next;
    }
    all
}

fn assert_exhaustive_windows(pattern: &str, alphabet: &[u8], maximum_length: usize) {
    let fre = portable(pattern);
    let oracle = oracle(pattern);
    let shortest_oracle = RegexBuilder::new(pattern)
        .unicode(false)
        .build()
        .unwrap_or_else(|error| panic!("shortest oracle build failed for {pattern:?}: {error}"));
    assert_eq!(
        fre.build_report().plan,
        PlanKind::LiteralClassRunLiteral,
        "pattern={pattern:?}"
    );
    assert!(fre.build_report().literal_class_run_literal.is_some());

    for haystack in byte_strings(maximum_length, alphabet) {
        for start in 0..=haystack.len() {
            for end in start..=haystack.len() {
                let expected = oracle
                    .find(Input::new(&haystack).span(start..end))
                    .map(|matched| (matched.start(), matched.end()));
                let (actual, accounting) = fre
                    .find_window(
                        &haystack,
                        SearchWindow::new(start, end),
                        SearchLimits::unlimited(),
                    )
                    .unwrap_or_else(|error| {
                        panic!(
                            "search failed pattern={pattern:?} haystack={haystack:?} window={start}..{end}: {error}"
                        )
                    });
                assert_eq!(
                    actual.map(|matched| (matched.start(), matched.end())),
                    expected,
                    "pattern={pattern:?} haystack={haystack:?} window={start}..{end}"
                );
                let SearchAccounting::LiteralClassRunLiteral(accounting) = accounting else {
                    panic!("wrong accounting family for {pattern:?}");
                };
                assert_eq!(accounting.window_bytes, end - start);
                assert!(accounting.work <= usize::try_from(accounting.work_upper_bound).unwrap());
                assert!(accounting.source_reads <= accounting.source_reads_upper_bound);
                assert_eq!(
                    fre.is_match_window(
                        &haystack,
                        SearchWindow::new(start, end),
                        SearchLimits::unlimited(),
                    )
                    .unwrap()
                    .0,
                    expected.is_some(),
                    "is_match pattern={pattern:?} haystack={haystack:?} window={start}..{end}"
                );
                assert_eq!(
                    fre.is_match_window_value(
                        &haystack,
                        SearchWindow::new(start, end),
                        SearchLimits::unlimited(),
                    )
                    .unwrap(),
                    expected.is_some(),
                    "is_match_value pattern={pattern:?} haystack={haystack:?} window={start}..{end}"
                );
                if end == haystack.len() {
                    assert_eq!(
                        fre.find_at(&haystack, start, SearchLimits::unlimited())
                            .unwrap()
                            .0
                            .map(|matched| (matched.start(), matched.end())),
                        expected,
                        "find_at pattern={pattern:?} haystack={haystack:?} start={start}"
                    );
                    assert_eq!(
                        fre.shortest_match_at(&haystack, start, SearchLimits::unlimited())
                            .unwrap()
                            .0,
                        shortest_oracle.shortest_match_at(&haystack, start),
                        "shortest_at pattern={pattern:?} haystack={haystack:?} start={start}"
                    );
                }
            }
        }
    }
}

#[test]
fn exhaustive_general_contained_suffix_and_guarded_windows_match_pinned_oracle() {
    assert_exhaustive_windows(r"ab[xy]+cd", b"abcdx\xff", 5);
    assert_exhaustive_windows(r"a[xy]+bbbb", b"abxz", 6);
    assert_exhaustive_windows(r"item[0-2]+", b"item0x", 5);
    assert_exhaustive_windows(r"[ab]+aba", b"abx\xff", 6);
    assert_exhaustive_windows(r"[\x80-\xFF]+\xFF\xFF", b"\x80\xffx", 5);
    assert_exhaustive_windows(r"\b\w+ing\b", b"agin!\xff", 5);
}

#[test]
fn selected_and_shortest_preserve_both_greedy_ambiguity_families() {
    let regex = portable(r"[ab]+aba");
    let haystack = b"!aababa!";
    let selected = regex
        .find(haystack, SearchLimits::unlimited())
        .unwrap()
        .0
        .map(|matched| (matched.start(), matched.end()));
    let shortest = regex
        .shortest_match(haystack, SearchLimits::unlimited())
        .unwrap()
        .0;
    let upstream = RegexBuilder::new(r"[ab]+aba")
        .unicode(false)
        .build()
        .unwrap();
    assert_eq!(selected, Some((1, 7)));
    assert_eq!(shortest, Some(5));
    assert_eq!(
        selected,
        upstream
            .find(haystack)
            .map(|matched| (matched.start(), matched.end()))
    );
    assert_eq!(shortest, upstream.shortest_match(haystack));

    let prefix_only = portable(r"item[0-2]+");
    let haystack = b"!item01221!";
    let selected = prefix_only
        .find(haystack, SearchLimits::unlimited())
        .unwrap()
        .0
        .map(|matched| (matched.start(), matched.end()));
    let shortest = prefix_only
        .shortest_match(haystack, SearchLimits::unlimited())
        .unwrap()
        .0;
    let upstream = RegexBuilder::new(r"item[0-2]+")
        .unicode(false)
        .build()
        .unwrap();
    assert_eq!(selected, Some((1, 10)));
    assert_eq!(shortest, Some(6));
    assert_eq!(
        selected,
        upstream
            .find(haystack)
            .map(|matched| (matched.start(), matched.end()))
    );
    assert_eq!(shortest, upstream.shortest_match(haystack));
}

#[test]
fn guarded_windows_keep_original_word_assertion_context() {
    let regex = portable(r"\b\w+ing\b");
    let locally_unicode_off = PortableBuilder::new(r"(?-u:\b\w+ing\b)").build().unwrap();
    assert_eq!(
        locally_unicode_off.build_report().plan,
        PlanKind::LiteralClassRunLiteral
    );
    let haystack = b"!testing! xing! \xffzing\x80";
    for (start, end, expected) in [
        (1, 8, Some((1, 8))),
        (2, 8, None),
        (1, 7, None),
        (10, 14, Some((10, 14))),
        (11, 14, None),
        (17, 21, Some((17, 21))),
    ] {
        let actual = regex
            .find_window(
                haystack,
                SearchWindow::new(start, end),
                SearchLimits::unlimited(),
            )
            .unwrap()
            .0
            .map(|matched| (matched.start(), matched.end()));
        assert_eq!(actual, expected, "window={start}..{end}");
        assert_eq!(
            locally_unicode_off
                .find_window(
                    haystack,
                    SearchWindow::new(start, end),
                    SearchLimits::unlimited(),
                )
                .unwrap()
                .0
                .map(|matched| (matched.start(), matched.end())),
            expected,
            "local Unicode-off window={start}..{end}"
        );
    }
}

#[test]
fn sessions_clones_and_nonoverlapping_iteration_reuse_the_source_plan() {
    let regex = portable(r"ab[ \t]+cd");
    let clone = regex.clone();
    let haystack = b"ab cd--ab \t cd--ab x cd--ab  cd";
    let expected: Vec<_> = oracle(r"ab[ \t]+cd")
        .find_iter(haystack)
        .map(|matched| (matched.start(), matched.end()))
        .collect();
    for regex in [&regex, &clone] {
        assert_eq!(regex.build_report().plan, PlanKind::LiteralClassRunLiteral);
        let mut session = regex
            .search_session(SearchSessionLimits::unlimited())
            .unwrap();
        let actual = session
            .find(haystack, SearchLimits::unlimited())
            .unwrap()
            .0
            .map(|matched| (matched.start(), matched.end()));
        assert_eq!(actual, expected.first().copied());

        let iterated: Vec<_> = regex
            .find_iter(haystack, PortableFindIterLimits::unlimited())
            .unwrap()
            .map(|item| {
                let matched = item.unwrap();
                (matched.start(), matched.end())
            })
            .collect();
        assert_eq!(iterated, expected);
    }
}

#[test]
fn established_specialized_routes_stay_ahead_of_the_general_plan() {
    assert_eq!(
        portable(r"[a-z]+Z").build_report().plan,
        PlanKind::RequiredLiteral
    );
    assert_eq!(
        portable(r"\b\w+\b").build_report().plan,
        PlanKind::UnicodeWordRun
    );
    assert_eq!(
        portable("literal").build_report().plan,
        PlanKind::ExactLiteral
    );
}

#[test]
#[allow(
    clippy::too_many_lines,
    reason = "all exact construction and search resource boundaries stay in one audit"
)]
fn planner_build_and_search_limits_have_exact_one_below_boundaries() {
    let baseline = portable(r"ab[ \t]+cd");
    let planner_work = baseline.build_report().planner_work;
    let build = baseline
        .build_report()
        .literal_class_run_literal
        .expect("source plan accounting");

    let exact_kernel = LiteralClassRunLiteralBuildLimits {
        max_literal_bytes: build.literal_bytes,
        max_class_ranges: build.class_ranges,
        max_class_members: build.class_members,
        max_build_work: build.work_upper_bound,
        max_scratch_bytes: build.scratch_bytes,
        max_persistent_bytes: build.persistent_bytes,
        max_peak_bytes: build.peak_bytes,
    };
    let exact_limits = BuildLimits {
        literal_class_run_literal: exact_kernel,
        max_planner_work: planner_work,
        ..BuildLimits::default()
    };
    assert!(
        PortableBuilder::new(r"ab[ \t]+cd")
            .unicode(false)
            .limits(exact_limits)
            .build()
            .is_ok()
    );
    assert!(matches!(
        PortableBuilder::new(r"ab[ \t]+cd")
            .unicode(false)
            .limits(BuildLimits {
                max_planner_work: planner_work - 1,
                ..BuildLimits::default()
            })
            .build(),
        Err(BuildError::PlannerWorkLimit { needed, limit })
            if needed == planner_work && limit == planner_work - 1
    ));
    for limited in [
        LiteralClassRunLiteralBuildLimits {
            max_literal_bytes: build.literal_bytes - 1,
            ..exact_kernel
        },
        LiteralClassRunLiteralBuildLimits {
            max_class_ranges: build.class_ranges - 1,
            ..exact_kernel
        },
        LiteralClassRunLiteralBuildLimits {
            max_class_members: build.class_members - 1,
            ..exact_kernel
        },
        LiteralClassRunLiteralBuildLimits {
            max_build_work: build.work_upper_bound - 1,
            ..exact_kernel
        },
        LiteralClassRunLiteralBuildLimits {
            max_persistent_bytes: build.persistent_bytes - 1,
            ..exact_kernel
        },
        LiteralClassRunLiteralBuildLimits {
            max_peak_bytes: build.peak_bytes - 1,
            ..exact_kernel
        },
    ] {
        assert!(matches!(
            PortableBuilder::new(r"ab[ \t]+cd")
                .unicode(false)
                .limits(BuildLimits {
                    literal_class_run_literal: limited,
                    ..BuildLimits::default()
                })
                .build(),
            Err(BuildError::LiteralClassRunLiteral(_))
        ));
    }

    let haystack = b"--ab    cd--";
    let (_, accounting) = baseline.find(haystack, SearchLimits::unlimited()).unwrap();
    let SearchAccounting::LiteralClassRunLiteral(accounting) = accounting else {
        panic!("wrong accounting family");
    };
    let exact_work = u64::try_from(accounting.work).unwrap();
    assert!(
        baseline
            .find(
                haystack,
                SearchLimits {
                    max_work: exact_work,
                    max_scratch_bytes: 0,
                },
            )
            .is_ok()
    );
    assert!(matches!(
        baseline.find(
            haystack,
            SearchLimits {
                max_work: exact_work - 1,
                max_scratch_bytes: 0,
            },
        ),
        Err(SearchError::LiteralClassRunLiteral(
            LiteralClassRunLiteralSearchError::WorkLimit { needed, limit }
        )) if needed == exact_work && limit == exact_work - 1
    ));
}
