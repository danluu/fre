#![forbid(unsafe_code)]

use std::alloc::System;

use fre_aot_regex::{
    CaptureCompileLimits, CaptureCompileRequest, CapturePrepareError, CaptureReplayStrategy,
    CaptureSessionLimits, CaptureSessionResource, CompileMode, SearchWindow, Target,
    compile_captures,
};
use stats_alloc::{INSTRUMENTED_SYSTEM, Region, Stats, StatsAlloc};

#[global_allocator]
static GLOBAL: &StatsAlloc<System> = &INSTRUMENTED_SYSTEM;

fn compile(force_history: bool) -> fre_aot_regex::CompiledCaptureRegex {
    let mut limits = CaptureCompileLimits::default();
    if force_history {
        limits.onepass.max_states = 0;
    }
    compile_captures(
        CaptureCompileRequest::new(r"(?P<a>a)b", Target::x86_64_linux())
            .mode(CompileMode::Fast)
            .limits(limits),
    )
    .expect("capture compilation")
}

#[test]
fn onepass_and_history_sessions_allocate_nothing_after_warmup() {
    let haystack = b"zzabzz";
    for force_history in [false, true] {
        let compiled = compile(force_history);
        let mut session = compiled
            .prepare_session(CaptureSessionLimits {
                max_haystack_bytes: haystack.len(),
                max_window_bytes: haystack.len(),
                ..CaptureSessionLimits::default()
            })
            .expect("session");
        if force_history {
            assert_eq!(
                CaptureReplayStrategy::PersistentHistory,
                session.replay_strategy()
            );
        } else {
            assert_eq!(CaptureReplayStrategy::OnePass, session.replay_strategy());
        }
        compiled
            .capture_with_session(&mut session, haystack, SearchWindow::full(haystack))
            .expect("warmup");
        let region = Region::new(GLOBAL);
        for _ in 0..32 {
            let report = compiled
                .capture_with_session(&mut session, haystack, SearchWindow::full(haystack))
                .expect("warm capture");
            assert!(report.matched);
            assert_eq!(Some((2, 4)), report.span);
        }
        assert_eq!(Stats::default(), region.change());
    }
    assert_exact_capture_persistent_cap_preflight();
}

fn assert_exact_capture_persistent_cap_preflight() {
    let haystack = b"zzabzz";
    for force_history in [false, true] {
        let compiled = compile(force_history);
        let base_limits = CaptureSessionLimits {
            max_haystack_bytes: haystack.len(),
            max_window_bytes: haystack.len(),
            ..CaptureSessionLimits::default()
        };
        let baseline = compiled
            .prepare_session(base_limits)
            .expect("baseline session");
        let required = baseline.capture_persistent_bytes();
        drop(baseline);

        let exact_limits = CaptureSessionLimits {
            max_capture_persistent_bytes: required,
            ..base_limits
        };
        let exact = compiled
            .prepare_session(exact_limits)
            .expect("exact persistent cap");
        assert_eq!(required, exact.capture_persistent_bytes());
        drop(exact);

        let one_below = CaptureSessionLimits {
            max_capture_persistent_bytes: required
                .checked_sub(1)
                .expect("capture session always retains storage"),
            ..base_limits
        };
        let region = Region::new(GLOBAL);
        let failure = compiled.prepare_session(one_below);
        let change = region.change();
        assert_eq!(Stats::default(), change);
        assert!(matches!(
            failure,
            Err(CapturePrepareError::Resource {
                resource: CaptureSessionResource::CapturePersistentBytes,
                required: observed,
                limit,
            }) if observed == required && limit.checked_add(1) == Some(observed)
        ));
    }
}
