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
fn exact_hir_text_captures_preserve_utf8_empty_and_group_boundaries() {
    let cases = [
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
    assert!(result.accounting.total_history_nodes <= result.accounting.total_state_visits);

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
    let error = regex
        .count_captures(b"a", starved)
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
    let regex = CaptureBuilder::new(r"(a)")
        .unicode(false)
        .build()
        .expect("combined-peak build");
    let admitted = regex
        .count_captures(b"a", CaptureRunLimits::default())
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
        .count_captures(b"a", constrained)
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

    let mut custom_line = fre::RustProfile::default();
    custom_line.options.line_terminator = b'\r';
    assert!(matches!(
        CaptureBuilder::new(r"(?m:^)(a)")
            .profile(custom_line)
            .build(),
        Err(fre::CaptureBuildError::Unsupported(
            fre::CaptureUnsupported::Look(_)
        ))
    ));
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
