#![forbid(unsafe_code)]

use fre_aot_regex::{
    CaptureAuthenticationError, CaptureCompileLimits, CaptureCompileRequest, CaptureGroupSlot,
    CaptureOnePassDisposition, CapturePrepareError, CaptureReplayStrategy, CaptureSearchError,
    CaptureSearchLimits, CaptureSessionLimits, CaptureSessionResource, CompileMode,
    CompiledProgram, OnePassCaptureBuildLimits, SearchWindow, SlowAotLimits, Target,
    compile_captures,
};
use fre_capture_lab::{CaptureProgramV1, CaptureProgramV1Limits, Span, Window};
use regex::bytes::Regex;

fn compile(pattern: &str, force_history: bool) -> fre_aot_regex::CompiledCaptureRegex {
    let mut limits = CaptureCompileLimits::default();
    if force_history {
        limits.onepass.max_states = 0;
    }
    compile_captures(
        CaptureCompileRequest::new(pattern, Target::x86_64_linux())
            .mode(CompileMode::Fast)
            .limits(limits),
    )
    .expect("capture compilation")
}

fn session_limits(haystack_len: usize) -> CaptureSessionLimits {
    CaptureSessionLimits {
        max_haystack_bytes: haystack_len,
        max_window_bytes: haystack_len,
        ..CaptureSessionLimits::default()
    }
}

fn slot_tuple(slot: CaptureGroupSlot) -> Option<(usize, usize)> {
    slot.span().map(|span| (span.start, span.end))
}

#[test]
fn capture_request_size_limit_controls_the_native_selector() {
    let target = Target::x86_64_linux();
    let default = CaptureCompileRequest::new("(a)", target);
    assert_eq!(default.limits.selector.max_program_bytes, 10 * 1_048_576);

    let mut limits = CaptureCompileLimits::default();
    limits.selector.max_program_bytes = 19 * 1_048_576;
    let limits_last = CaptureCompileRequest::new("(a)", target)
        .size_limit(17)
        .limits(limits);
    assert_eq!(
        limits_last.limits.selector.max_program_bytes,
        limits.selector.max_program_bytes
    );
    let size_last = CaptureCompileRequest::new("(a)", target)
        .limits(limits)
        .size_limit(17);
    assert_eq!(size_last.limits.selector.max_program_bytes, 17);

    let rebar = CaptureCompileRequest::new("(a)", target)
        .size_limit(17)
        .profile(fre_syntax::RustProfile::rebar_1_12_4());
    assert_eq!(
        rebar.limits.selector.max_program_bytes,
        fre_aot_regex::CompileLimitsV1::default().max_program_bytes
    );
}

#[test]
fn all_capture_slots_match_upstream_for_general_byte_patterns() {
    let cases: &[(&str, &[u8])] = &[
        (r"(?P<outer>a(?P<inner>b))(?P<optional>c)?", b"xxab yy"),
        (r"(?P<repeat>a(b)?)+", b"xaaab!"),
        (r"(?P<empty>a*)", b"bbb"),
        (r"(?P<byte>\xFF+)", b"x\xFF\xFFy"),
        (r"(?m)^(?P<line>[a-z]+)$", b"12\nabc\n34"),
        (r"(?Rm:^(?P<crlf>[a-z]+)$)", b"12\r\nabc\r\n34"),
        (r"(?P<greek>β+)", "xββy".as_bytes()),
    ];
    for &(pattern, haystack) in cases {
        let compiled = compile(pattern, false);
        let mut session = compiled
            .prepare_session(session_limits(haystack.len()))
            .expect("session");
        let report = compiled
            .capture_with_session(&mut session, haystack, SearchWindow::full(haystack))
            .expect("capture execution");
        let upstream = Regex::new(pattern)
            .expect("upstream pattern")
            .captures(haystack);
        assert_eq!(upstream.is_some(), report.matched, "pattern {pattern:?}");
        let expected = upstream.as_ref().map_or_else(
            || vec![None; compiled.capture_program().schema().group_count()],
            |captures| {
                (0..captures.len())
                    .map(|index| {
                        captures
                            .get(index)
                            .map(|matched| (matched.start(), matched.end()))
                    })
                    .collect::<Vec<_>>()
            },
        );
        let actual = session
            .groups()
            .iter()
            .copied()
            .map(slot_tuple)
            .collect::<Vec<_>>();
        assert_eq!(expected, actual, "pattern {pattern:?}");
        assert_eq!(actual.first().copied().flatten(), report.span);
    }
}

#[test]
fn selector_and_capture_roundtrip_independently_then_authenticate_as_a_pair() {
    let first = compile(r"(?P<first>a)", false);
    let selector_bytes = first
        .selector()
        .program()
        .serialize()
        .expect("selector bytes");
    let capture_bytes = first.capture_program().serialize().expect("capture bytes");
    let selector = CompiledProgram::deserialize(&selector_bytes).expect("selector restore");
    let capture = CaptureProgramV1::deserialize(&capture_bytes, CaptureProgramV1Limits::default())
        .expect("capture restore");
    first
        .receipt()
        .identity
        .authenticate(&selector, &capture)
        .expect("composite restore authentication");
    let expected_history_usage = first
        .capture_program()
        .history_exact_workspace_usage(1, CaptureSearchLimits::default())
        .expect("source-free stable workspace usage");
    let mut restored_workspace = first
        .capture_program()
        .prepare_history_exact_workspace(1, CaptureSearchLimits::default())
        .expect("stable workspace");
    assert_eq!(expected_history_usage, restored_workspace.usage());
    let mut restored_output = vec![CaptureGroupSlot::UNMATCHED; capture.schema().group_count()];
    let restored_run = capture
        .captures_exact_slots_with_history_workspace(
            &mut restored_workspace,
            b"a",
            Window::all(b"a"),
            Span { start: 0, end: 1 },
            &mut restored_output,
        )
        .expect("byte-identical artifact accepts digest-bound workspace");
    assert!(restored_run.matched);
    let detached_plan = first
        .capture_program()
        .try_onepass_capture_plan_accounted(OnePassCaptureBuildLimits::default())
        .expect("detached one-pass plan");
    let mut detached_workspace = detached_plan
        .create_workspace(CaptureSearchLimits::default())
        .expect("detached one-pass workspace");
    assert_eq!(
        detached_plan
            .workspace_usage(CaptureSearchLimits::default())
            .expect("source-free detached workspace usage"),
        detached_workspace.usage()
    );
    let mut detached_output = vec![CaptureGroupSlot::UNMATCHED; capture.schema().group_count()];
    let detached_run = capture
        .captures_exact_slots_with_onepass_workspace(
            &detached_plan,
            &mut detached_workspace,
            b"a",
            Window::all(b"a"),
            Span { start: 0, end: 1 },
            &mut detached_output,
            CaptureSearchLimits::default(),
        )
        .expect("byte-identical artifact accepts digest-bound one-pass plan and workspace");
    assert!(detached_run.matched);
    assert_eq!(Some((0, 1)), slot_tuple(detached_output[0]));
    assert_eq!(Some((0, 1)), slot_tuple(detached_output[1]));

    // Capture spelling does not affect the capture-free language here, but
    // the stable capture digest still prevents cross-pair substitution.
    let second = compile(r"(?P<second>a)", false);
    assert_eq!(
        Err(CaptureAuthenticationError::CaptureDigest),
        first
            .receipt()
            .identity
            .authenticate(&selector, second.capture_program())
    );
}

#[test]
fn fixed_history_workspace_is_transactional_and_enforces_exact_group_capacity() {
    let compiled = compile(r"(?P<a>a)(?P<missing>b)?", true);
    assert!(matches!(
        compiled.receipt().onepass,
        CaptureOnePassDisposition::Declined { .. }
    ));
    let haystack = b"a";
    let mut workspace = compiled
        .capture_program()
        .prepare_history_exact_workspace(haystack.len(), CaptureSearchLimits::default())
        .expect("history workspace");
    let mut short = vec![CaptureGroupSlot::matched(Span { start: 9, end: 9 }); 2];
    let before = short.clone();
    let error = compiled
        .capture_program()
        .captures_exact_slots_with_history_workspace(
            &mut workspace,
            haystack,
            Window::all(haystack),
            Span { start: 0, end: 1 },
            &mut short,
        )
        .expect_err("short group array");
    assert_eq!(CaptureSearchError::InvalidProgram, error);
    assert_eq!(before, short);

    let mut session = compiled
        .prepare_session(session_limits(haystack.len()))
        .expect("session");
    compiled
        .capture_with_session(&mut session, haystack, SearchWindow::full(haystack))
        .expect("initial success");
    let published = session.groups().to_vec();
    compiled
        .capture_with_session(&mut session, haystack, SearchWindow::new(0, 2))
        .expect_err("invalid window");
    assert_eq!(published, session.groups());
}

#[test]
fn successful_no_match_publishes_all_groups_as_unmatched() {
    let haystack = b"a!";
    for force_history in [false, true] {
        let compiled = compile(r"(?P<a>a)", force_history);
        let mut session = compiled
            .prepare_session(CaptureSessionLimits {
                max_haystack_bytes: haystack.len(),
                max_window_bytes: 1,
                ..CaptureSessionLimits::default()
            })
            .expect("session");
        for _ in 0..2 {
            let matched = compiled
                .capture_with_session(&mut session, haystack, SearchWindow::new(0, 1))
                .expect("matched publication");
            assert!(matched.matched);
            assert_eq!(Some((0, 1)), matched.span);
            assert!(session.groups().iter().all(|slot| !slot.is_unmatched()));
        }

        let unmatched = compiled
            .capture_with_session(&mut session, haystack, SearchWindow::new(1, 2))
            .expect("successful no-match publication");
        assert!(!unmatched.matched);
        assert_eq!(None, unmatched.span);
        assert!(unmatched.replay.is_none());
        assert!(session.groups().iter().all(|slot| slot.is_unmatched()));
    }
}

#[test]
fn session_resource_edges_are_typed_before_source() {
    let compiled = compile(r"(?P<a>a)(?P<b>b)?", true);
    let haystack = b"ab";
    let exact = compiled
        .prepare_session(session_limits(haystack.len()))
        .expect("baseline session");
    let persistent = exact.capture_persistent_bytes();
    let mut one_below = session_limits(haystack.len());
    one_below.max_capture_persistent_bytes = persistent - 1;
    assert!(matches!(
        compiled.prepare_session(one_below),
        Err(CapturePrepareError::Resource {
            resource: CaptureSessionResource::CapturePersistentBytes,
            required,
            limit,
        }) if required == persistent && limit + 1 == persistent
    ));
    let mut groups = session_limits(haystack.len());
    groups.max_groups = compiled.capture_program().schema().group_count() - 1;
    assert!(matches!(
        compiled.prepare_session(groups),
        Err(CapturePrepareError::Resource {
            resource: CaptureSessionResource::Groups,
            ..
        })
    ));
    let mut histories = session_limits(haystack.len());
    histories.replay.max_history_nodes = 0;
    assert!(matches!(
        compiled.prepare_session(histories),
        Err(CapturePrepareError::Replay(
            CaptureSearchError::Resource { .. }
        ))
    ));
}

#[test]
fn nonzero_windows_preserve_line_context_for_onepass_and_history() {
    let pattern = r"(?m)^(?P<line>[a-z]+)$";
    let haystack = b"xx\nabc\nzz";
    let window = SearchWindow::new(3, 6);
    let upstream = Regex::new(pattern)
        .expect("upstream pattern")
        .captures_at(haystack, window.start())
        .expect("upstream capture");
    let expected = (0..upstream.len())
        .map(|index| {
            upstream
                .get(index)
                .map(|matched| (matched.start(), matched.end()))
        })
        .collect::<Vec<_>>();

    for force_history in [false, true] {
        let compiled = compile(pattern, force_history);
        let mut session = compiled
            .prepare_session(CaptureSessionLimits {
                max_haystack_bytes: haystack.len(),
                max_window_bytes: window.end() - window.start(),
                ..CaptureSessionLimits::default()
            })
            .expect("bounded nonzero-window session");
        assert_eq!(
            if force_history {
                CaptureReplayStrategy::PersistentHistory
            } else {
                CaptureReplayStrategy::OnePass
            },
            session.replay_strategy()
        );
        let report = compiled
            .capture_with_session(&mut session, haystack, window)
            .expect("nonzero-window capture");
        assert_eq!(Some((3, 6)), report.span);
        assert_eq!(
            expected,
            session
                .groups()
                .iter()
                .copied()
                .map(slot_tuple)
                .collect::<Vec<_>>()
        );
    }
}

#[test]
fn selector_slow_aot_limits_are_plumbed_and_receipted() {
    let mut limits = CaptureCompileLimits::default();
    limits.selector.determinize.max_states = 0;
    let selected_limits = SlowAotLimits {
        max_native_data_bytes: usize::MAX,
        ..SlowAotLimits::default()
    };
    limits.selector_slow_aot = selected_limits;
    let selected = compile_captures(
        CaptureCompileRequest::new(r"(?P<body>[ab]+)z", Target::x86_64_linux())
            .mode(CompileMode::Optimizing)
            .limits(limits),
    )
    .expect("slow-AOT capture selector");
    assert_eq!(selected_limits, selected.receipt().selector_slow_aot);
    assert_eq!(
        selected_limits,
        selected
            .selector()
            .receipt()
            .slow_aot
            .as_ref()
            .expect("selected slow-AOT receipt")
            .requested_limits
    );

    let declined_limits = SlowAotLimits {
        max_allocation_bytes: 0,
        ..selected_limits
    };
    limits.selector_slow_aot = declined_limits;
    let declined = compile_captures(
        CaptureCompileRequest::new(r"(?P<body>[ab]+)z", Target::x86_64_linux())
            .mode(CompileMode::Optimizing)
            .limits(limits),
    )
    .expect("bounded ordinary selector fallback");
    assert_eq!(declined_limits, declined.receipt().selector_slow_aot);
    assert!(declined.selector().receipt().slow_aot.is_none());
}
