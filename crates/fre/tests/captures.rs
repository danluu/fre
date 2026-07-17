use fre::{
    CaptureAggregateLimits, CaptureBuilder, CaptureExecutionSource, CaptureResource,
    CaptureRunLimits, CaptureSearchError, CaptureSearchLimits, PortableTextCaptureBuilder,
};
use regex::RegexBuilder as TextRegexBuilder;
use regex::bytes::RegexBuilder;

type GroupFixture = (u32, Option<String>, Option<(usize, usize)>);
type CaptureFixture = Vec<GroupFixture>;

fn reference_count(pattern: &str, haystack: &[u8]) -> usize {
    let regex = RegexBuilder::new(pattern)
        .unicode(false)
        .build()
        .expect("reference pattern");
    regex
        .captures_iter(haystack)
        .map(|captures| captures.iter().flatten().count())
        .sum()
}

fn assert_count(pattern: &str, haystack: &[u8]) {
    let regex = CaptureBuilder::new(pattern)
        .unicode(false)
        .build()
        .expect("capture build");
    let result = regex
        .count_captures(haystack, CaptureRunLimits::default())
        .expect("capture reduction");
    assert_eq!(result.accounting.count, reference_count(pattern, haystack));
    assert_eq!(
        result.identity.plan,
        regex.cache_identity(CaptureRunLimits::default()).plan
    );
}

fn reference_records(pattern: &str, haystack: &[u8]) -> Vec<CaptureFixture> {
    let regex = RegexBuilder::new(pattern)
        .unicode(false)
        .build()
        .expect("reference pattern");
    let names = regex
        .capture_names()
        .map(|name| name.map(str::to_owned))
        .collect::<Vec<_>>();
    regex
        .captures_iter(haystack)
        .map(|captures| {
            captures
                .iter()
                .enumerate()
                .map(|(index, matched)| {
                    (
                        u32::try_from(index).unwrap(),
                        names[index].clone(),
                        matched.map(|matched| (matched.start(), matched.end())),
                    )
                })
                .collect()
        })
        .collect()
}

#[test]
fn materialized_capture_iteration_preserves_empty_unmatched_and_named_slots() {
    let cases: &[(&str, &[u8])] = &[
        (r"(a){0}(a)", b"a"),
        (r"(?P<left>a)|(b)", b"ab"),
        (r"()|a", b"a"),
        (r"(a*)", b"ba"),
        (r"((a)?)(b)?", b"ab b"),
        (r"(?-u:([\x80-\xFF]+))", &[0xFF, 0x80, b' ', 0xFE]),
    ];
    for &(pattern, haystack) in cases {
        let regex = CaptureBuilder::new(pattern)
            .unicode(false)
            .build()
            .unwrap_or_else(|error| panic!("pattern={pattern:?}: {error:?}"));
        let limits = CaptureAggregateLimits::default();
        let report = regex
            .captures_iter(haystack, limits)
            .unwrap_or_else(|error| panic!("pattern={pattern:?}: {error:?}"));
        let actual = report
            .captures
            .iter()
            .map(|captures| {
                captures
                    .groups
                    .iter()
                    .map(|group| {
                        (
                            group.index,
                            group.name.clone(),
                            group.span.map(|span| (span.start, span.end)),
                        )
                    })
                    .collect::<Vec<_>>()
            })
            .collect::<Vec<_>>();
        assert_eq!(actual, reference_records(pattern, haystack), "{pattern:?}");
        assert_eq!(report.identity, regex.iteration_identity(limits));
        assert_eq!(
            report.identity.syntax,
            regex.build_report().plan_identity.syntax
        );
    }
}

fn reference_text_records(pattern: &str, haystack: &str) -> Vec<CaptureFixture> {
    let regex = TextRegexBuilder::new(pattern)
        .build()
        .expect("reference text pattern");
    let names = regex
        .capture_names()
        .map(|name| name.map(str::to_owned))
        .collect::<Vec<_>>();
    regex
        .captures_iter(haystack)
        .map(|captures| {
            captures
                .iter()
                .enumerate()
                .map(|(index, matched)| {
                    (
                        u32::try_from(index).unwrap(),
                        names[index].clone(),
                        matched.map(|matched| (matched.start(), matched.end())),
                    )
                })
                .collect()
        })
        .collect()
}

#[test]
fn pinned_expensive_counted_text_captures_match_upstream() {
    // Pinned corpus identities:
    // - expensive/regression-many-repeat-no-stack-overflow
    // - expensive/backtrack-blow-visited-capacity
    let cases = [
        (r"^.{1,2500}", "a"),
        (
            r"\pL{50}",
            "abcdefghijklmnopqrstuvwxyabcdefghijklmnopqrstuvwxyabcdefghijklmnopqrstuvwxyabcdefghijklmnopqrstuvwxyabcdefghijklmnopqrstuvwxyabcdefghijklmnopqrstuvwxyZZ",
        ),
    ];
    for (pattern, haystack) in cases {
        let regex = PortableTextCaptureBuilder::new(pattern)
            .build()
            .unwrap_or_else(|error| panic!("pattern={pattern:?}: {error:?}"));
        let report = regex
            .captures_iter(haystack, CaptureAggregateLimits::default())
            .unwrap_or_else(|error| panic!("pattern={pattern:?}: {error:?}"));
        let actual = report
            .captures
            .iter()
            .map(|captures| {
                captures
                    .groups
                    .iter()
                    .map(|group| {
                        (
                            group.index,
                            group.name.clone(),
                            group.span.map(|span| (span.start, span.end)),
                        )
                    })
                    .collect::<CaptureFixture>()
            })
            .collect::<Vec<_>>();
        assert_eq!(
            actual,
            reference_text_records(pattern, haystack),
            "{pattern:?}"
        );
    }
}

#[test]
fn exact_hir_text_captures_preserve_utf8_empty_and_group_boundaries() {
    let cases = [
        (r"(a){0}(a)", "a"),
        (r"(?P<left>a)|(b)", "éab"),
        (r"()|a", "éa"),
        (r"(a*)", "éba"),
        (r"((a)?)(b)?", "éab b"),
        (r"(é+)", "aéé東京"),
        (r"(\w+)", "éa 東京_42"),
        (r"(.)", "é東京"),
        (r"^((?:é|a)*)$", "éaé"),
        (r"([\p{Greek}]+)", "aΔδ東京"),
        (r"(\b)", "éa 東京_42"),
        (r"(\B)", "éa 東京_42"),
        (r"(\b{start})", "éa 東京_42"),
        (r"(\b{end})", "éa 東京_42"),
        (r"(\b{start-half})", "éa 東京_42"),
        (r"(\b{end-half})", "éa 東京_42"),
        (r"(?m:^([^\n]*))", "éa\n東京\n"),
        (r"(?Rm:^([^\r\n]*))", "éa\r\n東京\r末"),
    ];
    for (pattern, haystack) in cases {
        let regex = PortableTextCaptureBuilder::new(pattern)
            .build()
            .unwrap_or_else(|error| panic!("pattern={pattern:?}: {error:?}"));
        let report = regex
            .captures_iter(haystack, CaptureAggregateLimits::default())
            .unwrap_or_else(|error| panic!("pattern={pattern:?}: {error:?}"));
        let actual = report
            .captures
            .iter()
            .map(|captures| {
                captures
                    .groups
                    .iter()
                    .map(|group| {
                        (
                            group.index,
                            group.name.clone(),
                            group.span.map(|span| (span.start, span.end)),
                        )
                    })
                    .collect::<CaptureFixture>()
            })
            .collect::<Vec<_>>();
        assert_eq!(
            actual,
            reference_text_records(pattern, haystack),
            "{pattern:?}"
        );
    }
}

#[test]
fn single_text_capture_view_supports_numeric_name_and_borrowed_indexing() {
    fn named_len(haystack: &str) -> usize {
        let regex = PortableTextCaptureBuilder::new(r"^(?P<name>.+)$")
            .build()
            .expect("text capture build");
        let (captures, accounting) = regex
            .captures(haystack, CaptureSearchLimits::default())
            .expect("bounded text capture search");
        assert!(accounting.state_visits > 0);
        let captures = captures.expect("capture record");
        captures["name"].len()
    }

    let regex = PortableTextCaptureBuilder::new(r"^(?P<name>.+)$")
        .build()
        .expect("text capture build");
    let (captures, _) = regex
        .captures("abc", CaptureSearchLimits::default())
        .expect("bounded text capture search");
    let captures = captures.expect("capture record");
    assert_eq!(captures.len(), 2);
    assert!(!captures.is_empty());
    assert_eq!(captures.get(0).expect("whole match").as_str(), "abc");
    assert_eq!(captures.get(1).expect("numeric group").as_str(), "abc");
    assert_eq!(captures.name("name").expect("named group").as_str(), "abc");
    assert_eq!(&captures[0], "abc");
    assert_eq!(&captures[1], "abc");
    assert_eq!(&captures["name"], "abc");
    assert_eq!(named_len("123"), 3);
}

#[test]
fn single_text_capture_indexing_panics_for_missing_slots_and_names() {
    let regex = PortableTextCaptureBuilder::new(r"^(?P<name>.+)$")
        .build()
        .expect("text capture build");
    let (captures, _) = regex
        .captures("abc", CaptureSearchLimits::default())
        .expect("bounded text capture search");
    let captures = captures.expect("capture record");
    assert!(std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| &captures[2])).is_err());
    assert!(
        std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| &captures["missing"])).is_err()
    );
}

#[test]
fn cross_family_capture_reducers_match_pinned_rust_bytes() {
    let cases: &[(&str, &[u8])] = &[
        (r"(a)(b)?", b"a ab"),
        (r"((a)|(b))+", b"abba cab"),
        (r"(?:fn is_(\w+)|fn as_(\w+))", b"fn is_a fn as_b"),
        (
            r"^\s*fn\s+(is_([^\(]+))\(([^)]+)\) -> bool \{$",
            b"fn is_even(x: u8) -> bool {",
        ),
        (r"(()a)", b"a"),
        (r"(?:\A(a)|(a))", b"xax"),
        (r"(?:(a)\z|(a))", b"xax"),
        (r"(?-u:([\x80-\xFF]+))", &[0xFF, 0x80, b' ', 0xFE]),
    ];
    for &(pattern, haystack) in cases {
        assert_count(pattern, haystack);
    }
}

#[test]
fn uniform_participation_uses_selector_without_history() {
    let cases: &[(&str, &[u8])] = &[
        (r"fn is_(\w+)|fn as_(\w+)", b"fn is_even fn as_byte"),
        (r"(?s)^((.*)()()($))", b"abc\ndef"),
        (
            r"cargo/registry/src/[^/]+/([0-9A-Za-z_-]+)-([0-9]+\.[0-9]+\.[0-9]+[0-9A-Za-z+.-]*)/",
            b"cargo/registry/src/x/name-1.2.3/",
        ),
        (
            r"cargo/registry/src/[^/]+/([0-9A-Za-z_-]+)-([0-9]+\.[0-9]+\.[0-9]+[0-9A-Za-z+.-]*)/|cargo\\registry\\src\\[^\\]+\\([0-9A-Za-z_-]+)-([0-9]+\.[0-9]+\.[0-9]+[0-9A-Za-z+.-]*)\\",
            b"cargo/registry/src/x/name-1.2.3/",
        ),
        (r"(a){0}(a)", b"a"),
    ];
    for &(pattern, haystack) in cases {
        let regex = CaptureBuilder::new(pattern)
            .unicode(false)
            .build()
            .unwrap_or_else(|error| panic!("pattern={pattern:?}: {error:?}"));
        assert_eq!(
            regex.build_report().plan_identity.plan,
            fre::CapturePlanKind::LinearSelectorUniformParticipation,
            "pattern={pattern:?}"
        );
        let limits = CaptureRunLimits {
            aggregate: CaptureAggregateLimits {
                per_search: CaptureSearchLimits {
                    max_state_visits: 0,
                    max_history_nodes: 0,
                    max_history_walk: 0,
                    ..CaptureSearchLimits::default()
                },
                max_total_state_visits: 0,
                max_total_history_nodes: 0,
                max_total_history_walk: 0,
                ..CaptureAggregateLimits::default()
            },
            ..CaptureRunLimits::default()
        };
        let result = regex
            .count_captures(haystack, limits)
            .unwrap_or_else(|error| panic!("pattern={pattern:?}: {error:?}"));
        assert_eq!(result.accounting.count, reference_count(pattern, haystack));
        assert_eq!(result.accounting.total_state_visits, 0);
        assert_eq!(result.accounting.total_history_nodes, 0);
        assert_eq!(result.accounting.total_history_walk, 0);
    }

    for pattern in [r"(a)(b)?", r"((a)|(b))+", r"(a)|(b)(c)"] {
        let regex = CaptureBuilder::new(pattern)
            .unicode(false)
            .build()
            .unwrap_or_else(|error| panic!("pattern={pattern:?}: {error:?}"));
        assert_eq!(
            regex.build_report().plan_identity.plan,
            fre::CapturePlanKind::LinearSelectorPersistentHistory,
            "pattern={pattern:?}"
        );
    }
}

#[test]
fn uniform_participation_preserves_count_and_event_limits() {
    let regex = CaptureBuilder::new(r"fn is_(\w+)|fn as_(\w+)")
        .unicode(false)
        .build()
        .expect("uniform alternation build");
    let haystack = b"fn is_even fn as_byte";
    let exact = regex
        .count_captures(haystack, CaptureRunLimits::default())
        .expect("uniform exact limits");
    assert_eq!(exact.accounting.matches, 2);
    assert_eq!(exact.accounting.count, 4);
    let count_starved = CaptureRunLimits {
        aggregate: CaptureAggregateLimits {
            max_capture_count: exact.accounting.count - 1,
            ..CaptureAggregateLimits::default()
        },
        ..CaptureRunLimits::default()
    };
    let count_error = regex
        .count_captures(haystack, count_starved)
        .expect_err("uniform count one below must refuse");
    assert!(matches!(
        count_error.source,
        CaptureExecutionSource::History(CaptureSearchError::Resource {
            kind: CaptureResource::CaptureCount,
            required: 4,
            limit: 3,
        })
    ));
    let event_starved = CaptureRunLimits {
        aggregate: CaptureAggregateLimits {
            max_capture_events: 5,
            ..CaptureAggregateLimits::default()
        },
        ..CaptureRunLimits::default()
    };
    let event_error = regex
        .count_captures(haystack, event_starved)
        .expect_err("uniform events one below must refuse");
    assert!(matches!(
        event_error.source,
        CaptureExecutionSource::History(CaptureSearchError::Resource {
            kind: CaptureResource::CaptureEvents,
            required: 6,
            limit: 5,
        })
    ));
}

#[test]
fn sixty_five_user_captures_match_pinned_rust_and_remain_bounded() {
    // This cardinality is shared by the authenticated Veryl lexer rows:
    // curated/05-lexer-veryl/single and wild/parol-veryl/{ascii,unicode}.
    let pattern = "(a)".repeat(65);
    let haystack = vec![b'a'; 65];
    let regex = CaptureBuilder::new(&pattern)
        .unicode(false)
        .build()
        .expect("65 user captures fit the facade's bounded default");
    assert_eq!(regex.build_report().engine.captures, 65);
    let result = regex
        .count_captures(&haystack, CaptureRunLimits::default())
        .expect("65-capture reduction");
    assert_eq!(
        result.accounting.count,
        reference_count(&pattern, &haystack)
    );

    let mut limits = fre::CaptureBuildLimits::default();
    limits.engine.max_captures = 64;
    assert!(matches!(
        CaptureBuilder::new(&pattern)
            .unicode(false)
            .limits(limits)
            .build(),
        Err(fre::CaptureBuildError::Engine(
            fre::CaptureEngineBuildError::Resource {
                kind: CaptureResource::Captures,
                required: 65,
                limit: 64,
            }
        ))
    ));
}

#[test]
fn overlapping_unicode_word_captures_fit_the_bounded_selector_default() {
    // Authenticated Rebar obligations:
    // - unicode/overlapping-words/english@rust/regex
    // - unicode/overlapping-words/russian@rust/regex
    let pattern = r"(\p{L}{14})|(\p{L}{13})|(\p{L}{12})|(\p{L}{11})|(\p{L}{10})|(\p{L}{9})|(\p{L}{8})|(\p{L}{7})|(\p{L}{6})|(\p{L}{5})";
    let regex = CaptureBuilder::new(pattern)
        .unicode(true)
        .build()
        .expect("overlapping Unicode-word selector fits the bounded default");
    assert_eq!(regex.build_report().selector.program_states, 390);
    assert_eq!(regex.build_report().selector.temporary_states_peak, 390);
    assert_eq!(regex.build_report().selector.program_bytes, 549_432);
    assert!(regex.build_report().selector.work >= 126_986);

    for haystack in [
        "abcdefghijklmn абвгдежзийклмн",
        "абвгдежзийклмн abcdefghijklmn",
    ] {
        let actual = regex
            .count_captures(haystack.as_bytes(), CaptureRunLimits::default())
            .expect("bounded Unicode-word capture reduction")
            .accounting
            .count;
        let expected = RegexBuilder::new(pattern)
            .unicode(true)
            .build()
            .expect("pinned Rust reference")
            .captures_iter(haystack.as_bytes())
            .map(|captures| captures.iter().flatten().count())
            .sum::<usize>();
        assert_eq!(actual, expected, "{haystack:?}");
    }

    let mut limits = fre::CaptureBuildLimits::default();
    limits.selector.max_program_states = 389;
    assert!(matches!(
        CaptureBuilder::new(pattern)
            .unicode(true)
            .limits(limits)
            .build(),
        Err(fre::CaptureBuildError::Selector(
            fre::AggregateEngineError::ResourceLimit {
                resource: fre::AggregateResource::ProgramStates,
                required: 390,
                limit: 389,
            }
        ))
    ));
}

fn adversarial_operation_work(size: usize) -> (usize, usize) {
    let regex = CaptureBuilder::new(r"(?:a.*z|a)")
        .unicode(false)
        .build()
        .expect("adversarial selector build");
    let haystack = vec![b'a'; size];
    let result = regex
        .count_captures(&haystack, CaptureRunLimits::default())
        .expect("operation-wide capture reduction");
    assert_eq!(size, result.accounting.matches);
    assert_eq!(size, result.accounting.count);
    assert_eq!(size, result.selector_certificate.output_matches);
    let state_visits = result
        .selector_accounting
        .state_evaluations
        .saturating_add(result.selector_accounting.replay_steps)
        .saturating_add(result.accounting.total_state_visits);
    (state_visits, result.accounting.total_history_nodes)
}

#[test]
fn operation_wide_selector_removes_quadratic_restart_work() {
    let samples = [64_usize, 128, 256, 512].map(adversarial_operation_work);
    for pair in samples.windows(2) {
        let (smaller_visits, smaller_histories) = pair[0];
        let (larger_visits, larger_histories) = pair[1];
        assert!(
            larger_visits <= smaller_visits.saturating_mul(5).div_ceil(2),
            "doubling input grew state visits from {smaller_visits} to {larger_visits}"
        );
        assert!(
            larger_histories <= smaller_histories.saturating_mul(5).div_ceil(2),
            "doubling input grew history nodes from {smaller_histories} to {larger_histories}"
        );
    }
}

#[test]
fn persistent_history_reports_fanout_and_refuses_node_starvation() {
    let pattern = r"(?:(a+)|(b+)|(c+)|(d+)|(e+)|(f+)|(g+)|(h+)|(i+)|(j+)|(k+)|(l+)|(m+)|(n+)|(o+)|(p+)|(q+)|(r+)|(s+)|(t+)|(u+)|(v+)|(w+)|(x+)|(y+)|(z+))";
    let regex = CaptureBuilder::new(pattern)
        .unicode(false)
        .build()
        .expect("fanout build");
    assert_eq!(regex.build_report().engine.captures, 26);
    let result = regex
        .count_captures(b"aaabbbccc", CaptureRunLimits::default())
        .expect("fanout reduction");
    assert_eq!(
        result.identity.plan.plan,
        fre::CapturePlanKind::LinearSelectorUniformParticipation
    );
    assert_eq!(result.accounting.total_history_nodes, 0);

    let history = CaptureBuilder::new(r"(a)(b)?")
        .unicode(false)
        .build()
        .expect("variable-participation build");
    let starved = CaptureRunLimits {
        aggregate: CaptureAggregateLimits {
            per_search: CaptureSearchLimits {
                max_history_nodes: 0,
                ..CaptureSearchLimits::default()
            },
            max_total_history_nodes: 0,
            ..CaptureAggregateLimits::default()
        },
        ..CaptureRunLimits::default()
    };
    let error = history
        .count_captures(b"ab", starved)
        .expect_err("history starvation must refuse");
    assert!(matches!(
        error.source,
        CaptureExecutionSource::History(CaptureSearchError::Resource {
            kind: CaptureResource::HistoryNodes,
            ..
        })
    ));
}

#[test]
fn combined_peak_caps_retained_selector_output_plus_replay_scratch() {
    let regex = CaptureBuilder::new(r"(a)(b)?")
        .unicode(false)
        .build()
        .expect("combined-peak build");
    let admitted = regex
        .count_captures(b"ab", CaptureRunLimits::default())
        .expect("combined-peak baseline");
    assert!(
        admitted.combined_peak_bytes > admitted.selector_accounting.peak_bytes,
        "fixture must expose retained spans plus replay scratch"
    );
    assert!(admitted.combined_peak_bytes <= CaptureRunLimits::default().max_combined_peak_bytes);

    let constrained = CaptureRunLimits {
        max_combined_peak_bytes: admitted.selector_accounting.peak_bytes,
        ..CaptureRunLimits::default()
    };
    let error = regex
        .count_captures(b"ab", constrained)
        .expect_err("combined peak must constrain replay before allocation");
    assert!(matches!(
        error.source,
        CaptureExecutionSource::History(CaptureSearchError::Resource {
            kind: CaptureResource::ScratchBytes,
            ..
        })
    ));
}

#[test]
fn unicode_capture_classes_and_admitted_contextual_looks_execute() {
    let pattern = r"([\p{L}\p{N}_]+)";
    let haystack = b"abc \xCE\x94\xCE\xB4 42 \xFF";
    let reference = RegexBuilder::new(pattern)
        .unicode(true)
        .build()
        .expect("Unicode byte reference")
        .captures_iter(haystack)
        .map(|captures| captures.iter().flatten().count())
        .sum::<usize>();
    let regex = CaptureBuilder::new(pattern)
        .unicode(true)
        .build()
        .expect("Unicode capture lowering");
    let actual = regex
        .count_captures(haystack, CaptureRunLimits::default())
        .expect("Unicode capture execution")
        .accounting
        .count;
    assert_eq!(actual, reference);
    let hir_starved = fre::CaptureBuildLimits {
        max_hir_work: regex.build_report().hir.work.saturating_sub(1),
        ..fre::CaptureBuildLimits::default()
    };
    assert!(matches!(
        CaptureBuilder::new(pattern)
            .unicode(true)
            .limits(hir_starved)
            .build(),
        Err(fre::CaptureBuildError::HirResource {
            resource: "work",
            ..
        })
    ));
    let engine = fre::CaptureEngineBuildLimits {
        max_ast_nodes: regex.build_report().engine.ast_nodes.saturating_sub(1),
        ..fre::CaptureEngineBuildLimits::default()
    };
    let ast_starved = fre::CaptureBuildLimits {
        engine,
        ..fre::CaptureBuildLimits::default()
    };
    assert!(matches!(
        CaptureBuilder::new(pattern)
            .unicode(true)
            .limits(ast_starved)
            .build(),
        Err(fre::CaptureBuildError::Engine(
            fre::CaptureEngineBuildError::Resource {
                kind: CaptureResource::AstNodes,
                ..
            }
        ))
    ));
    assert_count(r"(?m:^([^\n]+))", b"a\nb\n");
    assert_count(r"(?Rm:^([^\r\n]+))", b"a\r\nb\rc\n");
    assert_count(r"(?-u:\b)([A-Za-z_]+)(?-u:\b)", b"a-b_c 42");
    assert_count(r"(?-u:\b{start})([A-Za-z_]+)", b"a-b_c 42");
    let word_pattern = r"([\p{L}]+)\b";
    let word_haystack = "éa 東京_42".as_bytes();
    let word_reference = RegexBuilder::new(word_pattern)
        .unicode(true)
        .build()
        .expect("Unicode word reference")
        .captures_iter(word_haystack)
        .map(|captures| captures.iter().flatten().count())
        .sum::<usize>();
    let word_actual = CaptureBuilder::new(word_pattern)
        .unicode(true)
        .build()
        .expect("Unicode word capture")
        .count_captures(word_haystack, CaptureRunLimits::default())
        .expect("Unicode word execution")
        .accounting
        .count;
    assert_eq!(word_actual, word_reference);
}

#[test]
fn custom_line_terminator_captures_match_pinned_regex() {
    let cases: &[(&str, &[u8], u8)] = &[
        (r"(?m)^([a-z]+)$", b"\0abc\0", b'\0'),
        (r"(?m)^([a-z]+)$", b"\nabc\n", b'\0'),
        (r"(?m)^([a-z]+)$", &[0xFF, b'a', b'b', b'c', 0xFF], 0xFF),
        (r"(?m)^\b([a-z]+)\b$", b"ZabcZ", b'Z'),
        (r"(?m)^\B([a-z]+)\B$", b"ZabcZ", b'Z'),
        (r"(?m)^\b([a-z]+)\b$", b"%abc%", b'%'),
    ];
    for &(pattern, haystack, line_terminator) in cases {
        let mut reference_builder = RegexBuilder::new(pattern);
        reference_builder
            .unicode(false)
            .line_terminator(line_terminator);
        let reference = reference_builder
            .build()
            .unwrap_or_else(|error| panic!("reference pattern={pattern:?}: {error}"));
        let expected = reference
            .captures_iter(haystack)
            .map(|captures| {
                captures
                    .iter()
                    .map(|matched| matched.map(|matched| (matched.start(), matched.end())))
                    .collect::<Vec<_>>()
            })
            .collect::<Vec<_>>();

        let mut profile = fre::RustProfile::default();
        profile.options.unicode = false;
        profile.options.line_terminator = line_terminator;
        let regex = CaptureBuilder::new(pattern)
            .profile(profile)
            .build()
            .unwrap_or_else(|error| panic!("FRE pattern={pattern:?}: {error}"));
        let actual = regex
            .captures_iter(haystack, CaptureAggregateLimits::default())
            .unwrap_or_else(|error| panic!("FRE pattern={pattern:?}: {error}"))
            .captures
            .into_iter()
            .map(|captures| {
                captures
                    .groups
                    .into_iter()
                    .map(|group| group.span.map(|span| (span.start, span.end)))
                    .collect::<Vec<_>>()
            })
            .collect::<Vec<_>>();
        assert_eq!(
            actual, expected,
            "pattern={pattern:?}, line={line_terminator:#04X}"
        );
    }

    let pattern = r"(?m)^([\p{L}]+)$";
    let haystack = "!é東京!";
    let mut reference_builder = TextRegexBuilder::new(pattern);
    reference_builder.line_terminator(b'!');
    let expected = reference_builder
        .build()
        .expect("reference text pattern")
        .captures_iter(haystack)
        .map(|captures| {
            captures
                .iter()
                .map(|matched| matched.map(|matched| (matched.start(), matched.end())))
                .collect::<Vec<_>>()
        })
        .collect::<Vec<_>>();
    let mut profile = fre::RustProfile::default();
    profile.options.line_terminator = b'!';
    let actual = PortableTextCaptureBuilder::new(pattern)
        .profile(profile)
        .build()
        .expect("FRE text pattern")
        .captures_iter(haystack, CaptureAggregateLimits::default())
        .expect("FRE text captures")
        .captures
        .into_iter()
        .map(|captures| {
            captures
                .groups
                .into_iter()
                .map(|group| group.span.map(|span| (span.start, span.end)))
                .collect::<Vec<_>>()
        })
        .collect::<Vec<_>>();
    assert_eq!(actual, expected);
}

#[test]
fn source_and_execution_limits_remain_in_capture_identity() {
    let python_name = CaptureBuilder::new(r"(?P<letter>a)")
        .unicode(false)
        .build()
        .expect("Python-name spelling");
    let angle_name = CaptureBuilder::new(r"(?<letter>a)")
        .unicode(false)
        .build()
        .expect("angle-name spelling");
    assert_ne!(
        python_name.build_report().plan_identity,
        angle_name.build_report().plan_identity
    );

    let default_identity = python_name.cache_identity(CaptureRunLimits::default());
    let constrained = CaptureRunLimits {
        aggregate: CaptureAggregateLimits {
            max_capture_events: 1,
            ..CaptureAggregateLimits::default()
        },
        ..CaptureRunLimits::default()
    };
    assert_ne!(default_identity, python_name.cache_identity(constrained));
}
