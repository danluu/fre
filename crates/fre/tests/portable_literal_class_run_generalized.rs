#![allow(
    clippy::arithmetic_side_effects,
    reason = "exhaustive generators are bounded to small test inputs"
)]

use fre::{
    BuildError, BuildLimits, LITERAL_CLASS_RUN_GENERAL_SEARCH_PLAN_ID,
    LITERAL_CLASS_RUN_LITERAL_PLAN_ID, LiteralClassRunLiteralBuildLimits,
    LiteralClassRunLiteralSearchError, PlanKind, PortableBuilder, PortableFindIterLimits,
    SearchAccounting, SearchError, SearchLimits, SearchSessionLimits, SearchWindow,
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

fn shortest_oracle(pattern: &str) -> regex::bytes::Regex {
    RegexBuilder::new(pattern)
        .unicode(false)
        .build()
        .unwrap_or_else(|error| panic!("shortest oracle build failed for {pattern:?}: {error}"))
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

fn pseudo_random_bytes(length: usize, alphabet: &[u8], mut state: u64) -> Vec<u8> {
    let mut bytes = Vec::with_capacity(length);
    for _ in 0..length {
        state ^= state << 13;
        state ^= state >> 7;
        state ^= state << 17;
        let index = usize::try_from(state % u64::try_from(alphabet.len()).unwrap()).unwrap();
        bytes.push(alphabet[index]);
    }
    bytes
}

fn assert_exhaustive_windows(pattern: &str, alphabet: &[u8], maximum_length: usize) {
    let regex = portable(pattern);
    let oracle = oracle(pattern);
    let shortest = shortest_oracle(pattern);
    assert_eq!(regex.build_report().plan, PlanKind::LiteralClassRunLiteral);

    for haystack in byte_strings(maximum_length, alphabet) {
        for start in 0..=haystack.len() {
            for end in start..=haystack.len() {
                let expected = oracle
                    .find(Input::new(&haystack).span(start..end))
                    .map(|matched| (matched.start(), matched.end()));
                let (actual, accounting) = regex
                    .find_window(
                        &haystack,
                        SearchWindow::new(start, end),
                        SearchLimits::unlimited(),
                    )
                    .unwrap_or_else(|error| {
                        panic!(
                            "search failed pattern={pattern:?} haystack={haystack:?} \
                             window={start}..{end}: {error}"
                        )
                    });
                assert_eq!(
                    actual.map(|matched| (matched.start(), matched.end())),
                    expected,
                    "selected pattern={pattern:?} haystack={haystack:?} window={start}..{end}"
                );
                let SearchAccounting::LiteralClassRunLiteral(accounting) = accounting else {
                    panic!("wrong accounting family for {pattern:?}");
                };
                assert_eq!(accounting.window_bytes, end - start);
                assert!(accounting.work <= usize::try_from(accounting.work_upper_bound).unwrap());
                assert!(accounting.source_reads <= accounting.source_reads_upper_bound);
                assert!(accounting.candidate_visits <= accounting.candidate_visits_upper_bound);
                assert_eq!(
                    regex
                        .is_match_window(
                            &haystack,
                            SearchWindow::new(start, end),
                            SearchLimits::unlimited(),
                        )
                        .unwrap()
                        .0,
                    expected.is_some(),
                    "existence pattern={pattern:?} haystack={haystack:?} window={start}..{end}"
                );
                assert_eq!(
                    regex
                        .is_match_window_value(
                            &haystack,
                            SearchWindow::new(start, end),
                            SearchLimits::unlimited(),
                        )
                        .unwrap(),
                    expected.is_some(),
                    "value-only pattern={pattern:?} haystack={haystack:?} window={start}..{end}"
                );
                if end == haystack.len() {
                    assert_eq!(
                        regex
                            .shortest_match_at(&haystack, start, SearchLimits::unlimited(),)
                            .unwrap()
                            .0,
                        shortest.shortest_match_at(&haystack, start),
                        "shortest pattern={pattern:?} haystack={haystack:?} start={start}"
                    );
                }
            }
        }
    }
}

fn assert_metered_window_matches_oracle(pattern: &str, haystack: &[u8], start: usize, end: usize) {
    let regex = portable(pattern);
    let expected = oracle(pattern)
        .find(Input::new(haystack).span(start..end))
        .map(|matched| (matched.start(), matched.end()));
    let (unlimited, unlimited_accounting) = regex
        .find_window(
            haystack,
            SearchWindow::new(start, end),
            SearchLimits::unlimited(),
        )
        .unwrap_or_else(|error| {
            panic!(
                "unlimited search failed pattern={pattern:?} haystack={haystack:?} \
                 window={start}..{end}: {error}"
            )
        });
    assert_eq!(
        unlimited.map(|matched| (matched.start(), matched.end())),
        expected,
        "unlimited pattern={pattern:?} haystack={haystack:?} window={start}..{end}"
    );
    let SearchAccounting::LiteralClassRunLiteral(unlimited_accounting) = unlimited_accounting
    else {
        panic!("wrong unlimited accounting family for {pattern:?}");
    };
    let probe_limit = unlimited_accounting
        .work_upper_bound
        .checked_sub(1)
        .expect("literal/class-run search has nonzero fixed work");
    let (probe, probe_accounting) = regex
        .find_window(
            haystack,
            SearchWindow::new(start, end),
            SearchLimits {
                max_work: probe_limit,
                max_scratch_bytes: unlimited_accounting.scratch_bytes,
            },
        )
        .unwrap_or_else(|error| {
            panic!(
                "metered scalar probe failed pattern={pattern:?} haystack={haystack:?} \
                 window={start}..{end} max_work={probe_limit}: {error}"
            )
        });
    assert_eq!(
        probe.map(|matched| (matched.start(), matched.end())),
        expected,
        "metered probe pattern={pattern:?} haystack={haystack:?} window={start}..{end}"
    );
    let SearchAccounting::LiteralClassRunLiteral(probe_accounting) = probe_accounting else {
        panic!("wrong metered probe accounting family for {pattern:?}");
    };
    assert_eq!(
        probe_accounting.work_upper_bound,
        unlimited_accounting.work_upper_bound
    );
    assert!(u64::try_from(probe_accounting.work).unwrap() <= probe_limit);
    assert!(probe_accounting.work_upper_bound > probe_limit);

    let exact_work = u64::try_from(probe_accounting.work).unwrap();
    let (metered, metered_accounting) = regex
        .find_window(
            haystack,
            SearchWindow::new(start, end),
            SearchLimits {
                max_work: exact_work,
                max_scratch_bytes: unlimited_accounting.scratch_bytes,
            },
        )
        .unwrap_or_else(|error| {
            panic!(
                "exact metered search failed pattern={pattern:?} haystack={haystack:?} \
                 window={start}..{end} max_work={exact_work}: {error}"
            )
        });
    assert_eq!(
        metered.map(|matched| (matched.start(), matched.end())),
        expected,
        "metered pattern={pattern:?} haystack={haystack:?} window={start}..{end}"
    );
    let SearchAccounting::LiteralClassRunLiteral(metered_accounting) = metered_accounting else {
        panic!("wrong metered accounting family for {pattern:?}");
    };
    assert_eq!(metered_accounting.work, probe_accounting.work);
    assert_eq!(
        metered_accounting.source_reads,
        probe_accounting.source_reads
    );
    assert_eq!(
        metered_accounting.candidate_visits,
        probe_accounting.candidate_visits
    );
    assert!(u64::try_from(metered_accounting.work).unwrap() <= exact_work);
    assert!(metered_accounting.work_upper_bound > exact_work);
}

#[test]
fn generalized_and_singleton_shapes_have_stable_route_identity() {
    let singleton = portable(r"ab+c");
    assert_eq!(
        singleton.build_report().plan,
        PlanKind::LiteralClassRunLiteral
    );
    assert_eq!(
        singleton.runtime_implementation_id(),
        LITERAL_CLASS_RUN_LITERAL_PLAN_ID
    );

    for pattern in [
        r"a[^z\r\n]*z",
        r"a[ab]+c",
        r"a[bc]*",
        r"(?-u:\b[A-Za-z]+TRAILER\b)",
    ] {
        let regex = portable(pattern);
        assert_eq!(
            regex.build_report().plan,
            PlanKind::LiteralClassRunLiteral,
            "{pattern:?}"
        );
        assert_eq!(
            regex.runtime_implementation_id(),
            LITERAL_CLASS_RUN_GENERAL_SEARCH_PLAN_ID,
            "{pattern:?}"
        );
        assert!(
            regex.build_report().literal_class_run_literal.is_some(),
            "{pattern:?}"
        );
    }
}

#[test]
fn exhaustive_singleton_star_overlap_and_word_subset_match_oracles() {
    assert_exhaustive_windows(r"ab+c", b"abc!", 5);
    assert_exhaustive_windows(r"a[^z\r\n]*z", b"abz\r", 5);
    assert_exhaustive_windows(r"a[ab]+c", b"abc!", 5);
    assert_exhaustive_windows(r"a[bc]*", b"abc!", 5);
    assert_exhaustive_windows(r"\b[A-B]+T\b", b"ABT!0_\xff", 5);
}

#[test]
fn exhaustive_guarded_suffix_inside_class_windows_match_oracles() {
    assert_exhaustive_windows(r"\b[AB]+B\b", b"ABC!\x80\xff", 4);
    assert_exhaustive_windows(r"\b[A-T]+T\b", b"AMTU!\x80\xff", 4);
}

#[test]
fn prefix_only_star_preserves_selected_greediness_and_shortest_end() {
    let regex = portable(r"a[bc]*");
    let haystack = b"!abcb!ac!";
    assert_eq!(
        regex
            .find_accounted(haystack, SearchLimits::unlimited())
            .unwrap()
            .0
            .map(|matched| (matched.start(), matched.end())),
        Some((1, 5))
    );
    assert_eq!(
        regex
            .shortest_match(haystack, SearchLimits::unlimited())
            .unwrap()
            .0,
        Some(2)
    );
    let oracle = shortest_oracle(r"a[bc]*");
    assert_eq!(
        regex
            .find_accounted(haystack, SearchLimits::unlimited())
            .unwrap()
            .0
            .map(|matched| (matched.start(), matched.end())),
        oracle
            .find(haystack)
            .map(|matched| (matched.start(), matched.end()))
    );
    assert_eq!(
        regex
            .shortest_match(haystack, SearchLimits::unlimited())
            .unwrap()
            .0,
        oracle.shortest_match(haystack)
    );
}

#[test]
fn guarded_subset_uses_original_ascii_word_context_at_both_window_edges() {
    let regex = portable(r"\b[A-B]+T\b");
    let haystack = b"!AAT!_AAT!0AAT!\xffBAT\x80";
    for (start, end, expected, context) in [
        (1, 4, Some((1, 4)), 2),
        (2, 4, None, 2),
        (6, 9, None, 2),
        (11, 14, None, 2),
        (16, 19, Some((16, 19)), 2),
        (16, 20, Some((16, 19)), 1),
    ] {
        let (actual, accounting) = regex
            .find_window(
                haystack,
                SearchWindow::new(start, end),
                SearchLimits::unlimited(),
            )
            .unwrap();
        assert_eq!(
            actual.map(|matched| (matched.start(), matched.end())),
            expected,
            "window={start}..{end}"
        );
        let SearchAccounting::LiteralClassRunLiteral(accounting) = accounting else {
            panic!("wrong accounting family");
        };
        assert_eq!(accounting.assertion_context_bytes, context);
    }
}

#[test]
fn failed_overlapping_prefixes_skip_shared_runs_without_changing_results() {
    let mut haystack = vec![b'a'; 16_384];
    haystack.push(b'\r');
    haystack.extend_from_slice(b"--abbbz");
    let regex = portable(r"a[^z\r\n]*z");
    let expected = oracle(r"a[^z\r\n]*z")
        .find(&haystack)
        .map(|matched| (matched.start(), matched.end()));
    let (actual, accounting) = regex
        .find_accounted(&haystack, SearchLimits::unlimited())
        .unwrap();
    assert_eq!(
        actual.map(|matched| (matched.start(), matched.end())),
        expected
    );
    let SearchAccounting::LiteralClassRunLiteral(accounting) = accounting else {
        panic!("wrong accounting family");
    };
    assert!(accounting.work <= usize::try_from(accounting.work_upper_bound).unwrap());
    assert!(accounting.source_reads <= accounting.source_reads_upper_bound);
    assert!(accounting.candidate_visits <= accounting.candidate_visits_upper_bound);
}

#[test]
fn generalized_plan_survives_cloning_sessions_and_nonoverlapping_iteration() {
    let regex = portable(r"a[ab]*c");
    let clone = regex.clone();
    let haystack = b"aabbc--ac--aaX--abbbc";
    let expected: Vec<_> = oracle(r"a[ab]*c")
        .find_iter(haystack)
        .map(|matched| (matched.start(), matched.end()))
        .collect();
    for regex in [&regex, &clone] {
        assert_eq!(
            regex.runtime_implementation_id(),
            LITERAL_CLASS_RUN_GENERAL_SEARCH_PLAN_ID
        );
        let mut session = regex
            .search_session(SearchSessionLimits::unlimited())
            .unwrap();
        assert_eq!(
            session
                .find(haystack, SearchLimits::unlimited())
                .unwrap()
                .0
                .map(|matched| (matched.start(), matched.end())),
            expected.first().copied()
        );
        let actual: Vec<_> = regex
            .find_iter(haystack, PortableFindIterLimits::unlimited())
            .unwrap()
            .map(|item| {
                let matched = item.unwrap();
                (matched.start(), matched.end())
            })
            .collect();
        assert_eq!(actual, expected);
    }
}

#[test]
fn generalized_planner_build_and_search_limits_are_exact_at_the_facade() {
    let baseline = portable(r"a[ab]+c");
    let planner_work = baseline.build_report().planner_work;
    let build = baseline
        .build_report()
        .literal_class_run_literal
        .expect("generalized source-plan accounting");
    let exact_kernel = LiteralClassRunLiteralBuildLimits {
        max_literal_bytes: build.literal_bytes,
        max_class_ranges: build.class_ranges,
        max_class_members: build.class_members,
        max_build_work: build.work_upper_bound,
        max_scratch_bytes: build.scratch_bytes,
        max_persistent_bytes: build.persistent_bytes,
        max_peak_bytes: build.peak_bytes,
    };
    assert!(
        PortableBuilder::new(r"a[ab]+c")
            .unicode(false)
            .limits(BuildLimits {
                max_planner_work: planner_work,
                literal_class_run_literal: exact_kernel,
                ..BuildLimits::default()
            })
            .build()
            .is_ok()
    );
    assert!(matches!(
        PortableBuilder::new(r"a[ab]+c")
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
            PortableBuilder::new(r"a[ab]+c")
                .unicode(false)
                .limits(BuildLimits {
                    literal_class_run_literal: limited,
                    ..BuildLimits::default()
                })
                .build(),
            Err(BuildError::LiteralClassRunLiteral(_))
        ));
    }

    let haystack = b"--aaabc--";
    let (_, accounting) = baseline
        .find_accounted(haystack, SearchLimits::unlimited())
        .unwrap();
    let SearchAccounting::LiteralClassRunLiteral(accounting) = accounting else {
        panic!("wrong accounting family");
    };
    let exact_work = u64::try_from(accounting.work).unwrap();
    assert!(
        baseline
            .find_accounted(
                haystack,
                SearchLimits {
                    max_work: exact_work,
                    max_scratch_bytes: 0,
                },
            )
            .is_ok()
    );
    assert!(matches!(
        baseline.find_accounted(
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

#[test]
fn large_windows_meter_actual_work_instead_of_refusing_the_full_envelope() {
    for (pattern, matched) in [
        (r"ab[xy]+cd", b"abxycd".as_slice()),
        (r"a[ab]*c", b"aabbc".as_slice()),
        (r"\b[A-B]+T\b", b"AABT".as_slice()),
    ] {
        let regex = portable(pattern);
        let mut haystack = matched.to_vec();
        haystack.resize(8 * 1024 * 1024, b'!');
        let (actual, accounting) = regex
            .find_accounted(&haystack, SearchLimits::default())
            .unwrap_or_else(|error| panic!("large early match failed for {pattern:?}: {error}"));
        assert_eq!(
            actual.map(|matched| (matched.start(), matched.end())),
            Some((0, matched.len())),
            "{pattern:?}"
        );
        let SearchAccounting::LiteralClassRunLiteral(accounting) = accounting else {
            panic!("wrong accounting family");
        };
        assert!(
            accounting.work_upper_bound > SearchLimits::default().max_work,
            "test must exceed the old prospective refusal threshold for {pattern:?}"
        );
        assert!(
            u64::try_from(accounting.work).unwrap() < SearchLimits::default().max_work,
            "{pattern:?}"
        );
    }

    let regex = portable(r"a[ab]*c");
    let haystack = vec![b'x'; 1024 * 1024];
    assert!(matches!(
        regex.find_accounted(
            &haystack,
            SearchLimits {
                max_work: 64,
                max_scratch_bytes: 0,
            },
        ),
        Err(SearchError::LiteralClassRunLiteral(
            LiteralClassRunLiteralSearchError::WorkLimit {
                needed: 65,
                limit: 64
            }
        ))
    ));
}

#[test]
fn metered_scalar_interior_matches_and_no_match_tails_match_oracles() {
    let general = b"!!!!!!!!abxyxycd!!!!!!!!!!!!";
    let general_match = oracle(r"ab[xy]+cd").find(general).unwrap();
    assert_metered_window_matches_oracle(r"ab[xy]+cd", general, 0, general.len());
    assert_metered_window_matches_oracle(r"ab[xy]+cd", general, 3, general.len() - 3);
    assert_metered_window_matches_oracle(r"ab[xy]+cd", general, general_match.end(), general.len());

    let rejected = b"!!!!abxyxyce!!!!abxxxxx!!!!";
    assert_metered_window_matches_oracle(r"ab[xy]+cd", rejected, 0, rejected.len());
    assert_metered_window_matches_oracle(r"ab[xy]+cd", rejected, 2, rejected.len() - 2);

    let guarded = b"\xffCC!!AABB!!CC\x80";
    let guarded_match = oracle(r"\b[AB]+B\b").find(guarded).unwrap();
    assert_metered_window_matches_oracle(r"\b[AB]+B\b", guarded, 0, guarded.len());
    assert_metered_window_matches_oracle(r"\b[AB]+B\b", guarded, 2, guarded.len() - 2);
    assert_metered_window_matches_oracle(
        r"\b[AB]+B\b",
        guarded,
        guarded_match.end(),
        guarded.len(),
    );
}

#[test]
fn randomized_64_byte_to_megabyte_windows_and_iteration_match_oracles() {
    let cases: [(&str, &[u8], &[u8]); 9] = [
        (r"ab[xy]+cd", b"!abxycd!", b"!axycd"),
        (r"[ab]+aba", b"!aababa!", b"!ab"),
        (r"\b\w+ing\b", b"!testing!", b"!agin_"),
        (r"ya[xy]+bbbb", b"!yaxybbbb!", b"!yaxb"),
        (r"p[\x80-\xFF]+q", b"!p\x80\xffq!", b"!p\x80\xff"),
        (r"ab+c", b"!abbbc!", b"!abc"),
        (r"a[^z\r\n]*z", b"!abbbz!", b"!abz\r"),
        (r"a[ab]+c", b"!aaabc!", b"!abc"),
        (r"\b[A-B]+T\b", b"!ABAT!", b"!ABT0_"),
    ];
    for (case_index, (pattern, injection, alphabet)) in cases.into_iter().enumerate() {
        let regex = portable(pattern);
        let oracle = oracle(pattern);
        for (size_index, size) in [64_usize, 1024, 65_537, 1024 * 1024]
            .into_iter()
            .enumerate()
        {
            let seed = u64::try_from(case_index * 17 + size_index + 1).unwrap();
            let mut haystack = pseudo_random_bytes(size, alphabet, seed);
            let insertion = size / 3;
            let insertion_end = insertion + injection.len();
            haystack[insertion..insertion_end].copy_from_slice(injection);

            let expected = oracle
                .find(&haystack)
                .map(|matched| (matched.start(), matched.end()));
            let (actual, accounting) = regex
                .find_accounted(&haystack, SearchLimits::unlimited())
                .unwrap_or_else(|error| {
                    panic!("full search failed pattern={pattern:?} size={size}: {error}")
                });
            assert_eq!(
                actual.map(|matched| (matched.start(), matched.end())),
                expected,
                "full pattern={pattern:?} size={size}"
            );
            let SearchAccounting::LiteralClassRunLiteral(accounting) = accounting else {
                panic!("wrong accounting family for {pattern:?}");
            };
            assert!(accounting.work <= usize::try_from(accounting.work_upper_bound).unwrap());
            assert!(accounting.source_reads <= accounting.source_reads_upper_bound);

            for (start, end) in [
                (0, size),
                (size / 5, size - size / 7),
                (insertion, insertion_end),
                (insertion.saturating_sub(1), (insertion_end + 1).min(size)),
            ] {
                let expected = oracle
                    .find(Input::new(&haystack).span(start..end))
                    .map(|matched| (matched.start(), matched.end()));
                let actual = regex
                    .find_window(
                        &haystack,
                        SearchWindow::new(start, end),
                        SearchLimits::unlimited(),
                    )
                    .unwrap_or_else(|error| {
                        panic!(
                            "window search failed pattern={pattern:?} size={size} \
                             window={start}..{end}: {error}"
                        )
                    })
                    .0
                    .map(|matched| (matched.start(), matched.end()));
                assert_eq!(
                    actual, expected,
                    "window pattern={pattern:?} size={size} window={start}..{end}"
                );
            }

            let expected: Vec<_> = oracle
                .find_iter(&haystack)
                .map(|matched| (matched.start(), matched.end()))
                .collect();
            let actual: Vec<_> = regex
                .find_iter(&haystack, PortableFindIterLimits::unlimited())
                .unwrap()
                .map(|item| {
                    let matched = item.unwrap();
                    (matched.start(), matched.end())
                })
                .collect();
            assert_eq!(
                actual, expected,
                "iteration pattern={pattern:?} size={size}"
            );
        }
    }
}
