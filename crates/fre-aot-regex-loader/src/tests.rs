use std::{io, ptr, sync::Mutex};

use fre_aot_regex::{
    CompileMode, CompileRequest, CompileRequestV2, ExactFiniteSelectedEndTeddyPolicyV2,
    MatchResult, OutputContract, StartAccelerator, compile, compile_v2,
};

use super::*;

static PUBLICATION_TEST_LOCK: Mutex<()> = Mutex::new(());

#[test]
fn current_thread_sve_vector_length_receipt_is_structurally_valid_when_applicable() {
    let target = host_target().expect("supported test host");
    if target
        .features
        .contains(FeatureSet::of(CpuFeature::Aarch64Sve))
    {
        let bytes = current_thread_sve_vector_length_bytes()
            .expect("query current-thread SVE vector length")
            .expect("SVE target has an applicable vector-length receipt");
        assert!((16..=256).contains(&bytes));
        assert_eq!(bytes % 16, 0);
    } else if !cfg!(all(target_arch = "aarch64", target_os = "linux")) {
        assert_eq!(
            current_thread_sve_vector_length_bytes()
                .expect("non-Linux/AArch64 SVE query is inapplicable"),
            None
        );
    }
}

fn compile_span(pattern: &str) -> CompiledRegex {
    let compiled = compile(
        CompileRequest::new(pattern, host_target().expect("supported test host"))
            .mode(CompileMode::Optimizing)
            .output(OutputContract::Span),
    )
    .unwrap_or_else(|error| panic!("compile direct Span {pattern:?}: {error}"));
    let unresolved = compiled
        .module()
        .required_runtime_symbols()
        .collect::<Vec<_>>();
    assert!(
        unresolved.is_empty(),
        "fixture {pattern:?} unexpectedly requires {unresolved:?}"
    );
    compiled
}

fn compile_selected_end(pattern: &str) -> CompiledRegex {
    let compiled = compile(
        CompileRequest::new(pattern, host_target().expect("supported test host"))
            .mode(CompileMode::Optimizing)
            .output(OutputContract::SelectedEnd),
    )
    .unwrap_or_else(|error| panic!("compile direct SelectedEnd {pattern:?}: {error}"));
    let unresolved = compiled
        .module()
        .required_runtime_symbols()
        .collect::<Vec<_>>();
    assert!(
        unresolved.is_empty(),
        "fixture {pattern:?} unexpectedly requires {unresolved:?}"
    );
    compiled
}

fn portable_span(
    compiled: &CompiledRegex,
    haystack: &[u8],
    window: SearchWindow,
) -> Option<SpanMatch> {
    match compiled.search(haystack, window).expect("portable oracle") {
        MatchResult::Span(found) => found.map(|(start, end)| SpanMatch { start, end }),
        other => panic!("Span compiler returned {other:?}"),
    }
}

fn portable_selected_end(
    compiled: &CompiledRegex,
    haystack: &[u8],
    window: SearchWindow,
) -> Option<usize> {
    match compiled.search(haystack, window).expect("portable oracle") {
        MatchResult::SelectedEnd(found) => found,
        other => panic!("SelectedEnd compiler returned {other:?}"),
    }
}

#[allow(
    unsafe_code,
    reason = "the protection test forks a disposable child to attempt one forbidden mapped-page write"
)]
fn child_write_is_blocked(pointer: NonNull<c_void>) -> bool {
    // SAFETY: fork duplicates this process. The child performs only one
    // volatile store and async-signal-safe `_exit`, with no allocation or
    // synchronization after the fork.
    let child = unsafe { libc::fork() };
    assert!(
        child >= 0,
        "fork protection probe: {}",
        io::Error::last_os_error()
    );
    if child == 0 {
        // SAFETY: this deliberate write targets a live readable page. Correct
        // final protection terminates the child before the byte can change.
        unsafe {
            ptr::write_volatile(pointer.as_ptr().cast::<u8>(), 0);
            libc::_exit(0);
        }
    }
    let mut status = 0;
    loop {
        // SAFETY: `child` is the positive PID returned by fork and status is
        // initialized writable storage; no other thread owns this child.
        let waited = unsafe { libc::waitpid(child, &raw mut status, 0) };
        if waited == child {
            break;
        }
        if waited < 0 && io::Error::last_os_error().raw_os_error() == Some(libc::EINTR) {
            continue;
        }
        panic!("waitpid protection probe: {}", io::Error::last_os_error());
    }
    libc::WIFSIGNALED(status) && matches!(libc::WTERMSIG(status), libc::SIGBUS | libc::SIGSEGV)
}

#[test]
fn public_types_are_send_and_sync() {
    fn assert_send_sync<T: Send + Sync>() {}
    assert_send_sync::<PublishedSpan>();
    assert_send_sync::<PublishedSelectedEnd>();
    assert_send_sync::<SpanMatches<'_, '_>>();
}

#[test]
fn direct_selected_end_matches_portable_for_full_and_subwindows() {
    let _lock = PUBLICATION_TEST_LOCK.lock().unwrap();
    for (pattern, haystacks) in [
        (
            "a{0,100}b",
            [b"zzzaaabzz".as_slice(), b"aaaaaaaaac".as_slice()],
        ),
        ("(?:ab|a)", [b"zzabaz".as_slice(), b"nothing".as_slice()]),
        (
            r"(?-u:\b(?:foo|bar)\b)",
            [b"!foo bar!".as_slice(), b"foobar".as_slice()],
        ),
        (r"\Afoo", [b"foo bar".as_slice(), b"xfoo".as_slice()]),
        (r"foo\z", [b"xfoo".as_slice(), b"foo x".as_slice()]),
    ] {
        let compiled = compile_selected_end(pattern);
        let portable = compiled.clone();
        let receipt = compiled.receipt().clone();
        let published = publish_selected_end(compiled, PublicationLimits::default())
            .unwrap_or_else(|error| panic!("publish {pattern:?}: {error}"));
        assert_eq!(published.identity().as_bytes(), &receipt.object_sha256);
        assert_eq!(published.target(), receipt.target);
        assert_eq!(published.accounting().code_bytes(), receipt.code_bytes);
        for haystack in haystacks {
            for window in [
                SearchWindow::full(haystack),
                SearchWindow::new(0, haystack.len().saturating_sub(1)),
                SearchWindow::new(haystack.len().min(2), haystack.len()),
            ] {
                assert_eq!(
                    published.search(haystack, window).unwrap(),
                    portable_selected_end(&portable, haystack, window),
                    "{pattern:?} {haystack:?} {window:?}"
                );
            }
        }
    }
}

#[test]
fn forced_v2_accelerated_incumbent_executes_in_source_order_across_windows() {
    let _lock = PUBLICATION_TEST_LOCK.lock().unwrap();
    let target = host_target().expect("supported test host");
    let teddy_capable = target
        .features
        .contains(FeatureSet::of(CpuFeature::X86Avx2))
        || target
            .features
            .contains(FeatureSet::of(CpuFeature::Aarch64Asimd));
    if !teddy_capable {
        return;
    }
    for pattern in ["samwise|samw|frodo|pippin", "samw|samwise|frodo|pippin"] {
        let compiled = compile_v2(
            CompileRequestV2::new(
                CompileRequest::new(pattern, target)
                    .mode(CompileMode::Optimizing)
                    .output(OutputContract::SelectedEnd),
            )
            .exact_finite_selected_end_teddy(
                ExactFiniteSelectedEndTeddyPolicyV2::ForceStructurallyEligible,
            ),
        )
        .unwrap_or_else(|error| panic!("compile forced V2 {pattern:?}: {error}"));
        let report = compiled
            .receipt_v2()
            .exact_finite_selected_end_teddy_aot
            .unwrap_or_else(|| panic!("host target did not select forced V2 for {pattern:?}"));
        assert!(report.lowering.incumbent_complete_dfa.has_accelerator);
        assert_ne!(report.incumbent_start_accelerator, StartAccelerator::None);

        let mut haystack = vec![b'x'; 9_000];
        haystack[211..218].copy_from_slice(b"samwise");
        haystack[5_013..5_020].copy_from_slice(b"samwise");
        haystack[8_990..8_996].copy_from_slice(b"pippin");
        let windows = [
            SearchWindow::full(&haystack),
            SearchWindow::new(200, 215),
            SearchWindow::new(212, haystack.len()),
            SearchWindow::new(180, 260),
            SearchWindow::new(300, 5_013),
            SearchWindow::new(5_013, 5_017),
            SearchWindow::new(8_980, haystack.len()),
        ];
        let expected = windows
            .iter()
            .map(|&window| portable_selected_end(compiled.compiled(), &haystack, window))
            .collect::<Vec<_>>();
        let published =
            publish_selected_end(compiled.into_compiled(), PublicationLimits::default())
                .unwrap_or_else(|error| panic!("publish forced V2 {pattern:?}: {error}"));
        for (&window, expected) in windows.iter().zip(expected) {
            assert_eq!(
                published.search(&haystack, window).unwrap(),
                expected,
                "forced native/portable source-order parity for {pattern:?} in {window:?}",
            );
        }
    }
}

#[test]
fn direct_subwindows_preserve_full_haystack_anchor_context() {
    let _lock = PUBLICATION_TEST_LOCK.lock().unwrap();
    let haystack = b"prefix-tail-suffix";
    let window = SearchWindow::new(7, 11);
    for (pattern, window, expected) in [
        (r"tail\z", window, None),
        (r"\Atail", window, None),
        (r"(?:)", window, Some(7)),
        (r"\Aprefix", SearchWindow::new(0, 6), Some(6)),
        (r"suffix\z", SearchWindow::new(12, haystack.len()), Some(18)),
        (
            r"\z",
            SearchWindow::new(haystack.len(), haystack.len()),
            Some(haystack.len()),
        ),
    ] {
        let compiled = compile_selected_end(pattern);
        let portable = compiled.clone();
        let published = publish_selected_end(compiled, PublicationLimits::default())
            .unwrap_or_else(|error| panic!("publish {pattern:?}: {error}"));
        let portable_end = portable_selected_end(&portable, haystack, window);
        assert_eq!(
            published.search(haystack, window).unwrap(),
            portable_end,
            "native/portable parity for {pattern:?} in {window:?}"
        );
        assert_eq!(portable_end, expected, "{pattern:?} in {window:?}");
    }

    let compiled = compile_span(r"tail\z");
    let portable = compiled.clone();
    let span = publish_span(compiled, PublicationLimits::default())
        .expect("publish full-context bounded Span matcher");
    assert_eq!(
        span.search(haystack, window).unwrap(),
        portable_span(&portable, haystack, window)
    );
    assert_eq!(span.search(haystack, window).unwrap(), None);
}

#[test]
fn convenience_compile_and_publish_wrappers_use_the_detected_host_target() {
    let _lock = PUBLICATION_TEST_LOCK.lock().unwrap();
    let request = CompileRequest::new("needle", host_target().unwrap())
        .mode(CompileMode::Optimizing)
        .output(OutputContract::Span);
    let published = compile_and_publish_span(request, PublicationLimits::default()).unwrap();
    assert_eq!(
        published.find(b"hay needle stack").unwrap(),
        Some(SpanMatch { start: 4, end: 10 })
    );

    let request = CompileRequest::new("needle", host_target().unwrap())
        .mode(CompileMode::Optimizing)
        .output(OutputContract::SelectedEnd);
    let published =
        compile_and_publish_selected_end(request, PublicationLimits::default()).unwrap();
    assert_eq!(published.find(b"hay needle stack").unwrap(), Some(10));
}

#[test]
fn direct_span_matches_portable_for_full_and_subwindows() {
    let _lock = PUBLICATION_TEST_LOCK.lock().unwrap();
    for (pattern, haystacks) in [
        (
            "a{0,100}b",
            [b"zzzaaabzz".as_slice(), b"aaaaaaaaac".as_slice()],
        ),
        ("(?:ab|a)", [b"zzabaz".as_slice(), b"nothing".as_slice()]),
        (
            r"(?-u:\b(?:foo|bar)\b)",
            [b"!foo bar!".as_slice(), b"foobar".as_slice()],
        ),
    ] {
        let compiled = compile_span(pattern);
        let portable = compiled.clone();
        let receipt = compiled.receipt().clone();
        let published = publish_span(compiled, PublicationLimits::default())
            .unwrap_or_else(|error| panic!("publish {pattern:?}: {error}"));
        assert_eq!(published.identity().as_bytes(), &receipt.object_sha256);
        assert_eq!(published.target(), receipt.target);
        assert_eq!(published.accounting().code_bytes(), receipt.code_bytes);
        assert_eq!(
            published.accounting().read_only_data_bytes(),
            receipt.data_bytes
        );
        for haystack in haystacks {
            for window in [
                SearchWindow::full(haystack),
                SearchWindow::new(0, haystack.len().saturating_sub(1)),
                SearchWindow::new(haystack.len().min(2), haystack.len()),
            ] {
                assert_eq!(
                    published.search(haystack, window).unwrap(),
                    portable_span(&portable, haystack, window),
                    "{pattern:?} {haystack:?} {window:?}"
                );
            }
        }
    }
}

#[test]
fn iterator_preserves_nonoverlap_and_empty_match_progress() {
    let _lock = PUBLICATION_TEST_LOCK.lock().unwrap();
    let compiled = compile_span("(?:ab|a)");
    let published = publish_span(compiled, PublicationLimits::default()).unwrap();
    let actual = published
        .find_iter(b"ababa")
        .collect::<Result<Vec<_>, _>>()
        .unwrap();
    assert_eq!(
        actual,
        vec![
            SpanMatch { start: 0, end: 2 },
            SpanMatch { start: 2, end: 4 },
            SpanMatch { start: 4, end: 5 },
        ]
    );
    let bounded = published
        .find_iter_in(b"zabaz", SearchWindow::new(1, 4))
        .unwrap()
        .collect::<Result<Vec<_>, _>>()
        .unwrap();
    assert_eq!(
        bounded,
        vec![
            SpanMatch { start: 1, end: 3 },
            SpanMatch { start: 3, end: 4 },
        ]
    );

    let nullable = compile_span("a*");
    let nullable = publish_span(nullable, PublicationLimits::default()).unwrap();
    let actual = nullable
        .find_iter(b"ba")
        .collect::<Result<Vec<_>, _>>()
        .unwrap();
    let expected = regex::bytes::Regex::new("a*")
        .unwrap()
        .find_iter(b"ba")
        .map(|matched| SpanMatch {
            start: matched.start(),
            end: matched.end(),
        })
        .collect::<Vec<_>>();
    assert_eq!(actual, expected);
}

#[test]
fn published_mapping_is_reentrant_and_lives_through_last_clone() {
    let _lock = PUBLICATION_TEST_LOCK.lock().unwrap();
    let before = platform::live_mappings();
    let compiled = compile_span("a{0,100}b");
    let published = publish_span(compiled, PublicationLimits::default()).unwrap();
    assert_eq!(platform::live_mappings(), before + 1);

    std::thread::scope(|scope| {
        for _ in 0..8 {
            let matcher = published.clone();
            scope.spawn(move || {
                for _ in 0..1_000 {
                    assert_eq!(
                        matcher.find_at(b"xxaaaaabyy", 0).unwrap(),
                        Some(SpanMatch { start: 2, end: 8 })
                    );
                }
            });
        }
    });
    let clone = published.clone();
    drop(published);
    assert_eq!(platform::live_mappings(), before + 1);
    assert_eq!(
        clone.find(b"b").unwrap(),
        Some(SpanMatch { start: 0, end: 1 })
    );
    drop(clone);
    assert_eq!(platform::live_mappings(), before);
}

#[test]
fn published_mapping_has_distinct_guards_text_and_data_protections() {
    let _lock = PUBLICATION_TEST_LOCK.lock().unwrap();
    let before = platform::live_mappings();
    let published = publish_span(compile_span("a{0,100}b"), PublicationLimits::default()).unwrap();
    let accounting = published.accounting();
    assert!(accounting.code_bytes() > 0);
    assert!(accounting.read_only_data_bytes() > 0);
    let page = accounting.page_bytes();
    let text_offset = page;
    let text_mapped = accounting
        .code_bytes()
        .checked_add(page - 1)
        .map(|bytes| bytes & !(page - 1))
        .unwrap();
    let data_offset = text_offset.checked_add(text_mapped).unwrap();
    let right_guard_offset = accounting.total_mapped_bytes().checked_sub(page).unwrap();
    let mapping = &published.inner.mapping;

    assert_eq!(mapping.protection(0).unwrap(), libc::PROT_NONE);
    assert_eq!(
        mapping.protection(text_offset).unwrap(),
        libc::PROT_READ | libc::PROT_EXEC
    );
    assert_eq!(mapping.protection(data_offset).unwrap(), libc::PROT_READ);
    assert_eq!(
        mapping.protection(right_guard_offset).unwrap(),
        libc::PROT_NONE
    );
    assert!(child_write_is_blocked(
        mapping.pointer(text_offset).unwrap()
    ));
    assert!(child_write_is_blocked(
        mapping.pointer(data_offset).unwrap()
    ));

    drop(published);
    assert_eq!(platform::live_mappings(), before);
}

#[test]
fn helper_backed_and_wrong_output_artifacts_fail_closed_before_mapping() {
    let _lock = PUBLICATION_TEST_LOCK.lock().unwrap();
    let target = host_target().unwrap();
    let helper = compile(
        CompileRequest::new("a+", target)
            .mode(CompileMode::Fast)
            .output(OutputContract::Span),
    )
    .unwrap();
    let before = platform::live_mappings();
    let error = publish_span(helper, PublicationLimits::default()).unwrap_err();
    let PublicationError::RuntimeHelperRequired { symbol } = error else {
        panic!("helper-backed artifact returned {error:?}")
    };
    assert!(symbol.starts_with("fre_aot_regex_runtime_"), "{symbol}");
    assert_eq!(platform::live_mappings(), before);

    let exists = compile(
        CompileRequest::new("needle", target)
            .mode(CompileMode::Optimizing)
            .output(OutputContract::Exists),
    )
    .unwrap();
    assert!(matches!(
        publish_span(exists, PublicationLimits::default()),
        Err(PublicationError::OutputMismatch {
            expected: OutputContract::Span,
            actual: OutputContract::Exists,
        })
    ));

    let span = compile_span("needle");
    assert!(matches!(
        publish_selected_end(span, PublicationLimits::default()),
        Err(PublicationError::OutputMismatch {
            expected: OutputContract::SelectedEnd,
            actual: OutputContract::Span,
        })
    ));
    assert_eq!(platform::live_mappings(), before);
}

#[test]
fn exact_code_limit_rejects_without_reserving_pages() {
    let _lock = PUBLICATION_TEST_LOCK.lock().unwrap();
    let compiled = compile_span("a{0,100}b");
    let before = platform::live_mappings();
    let mut limits = PublicationLimits::default();
    let code_bytes = compiled.receipt().code_bytes;
    limits.max_code_bytes = code_bytes - 1;
    assert!(matches!(
        publish_span(compiled.clone(), limits),
        Err(PublicationError::Resource {
            resource: PublicationResource::CodeBytes,
            needed,
            limit,
        }) if needed == code_bytes && limit + 1 == needed
    ));
    assert_eq!(platform::live_mappings(), before);

    limits.max_code_bytes = code_bytes;
    let published = publish_span(compiled, limits).expect("exact code boundary");
    assert_eq!(
        published.find(b"aaab").unwrap(),
        Some(SpanMatch { start: 0, end: 4 })
    );
}

fn relocation(kind: RelocationKind, addend: i64) -> ModuleRelocation {
    ModuleRelocation {
        section: 0,
        offset: 0,
        kind,
        symbol: 0,
        addend,
    }
}

#[test]
fn x86_relocations_use_elf_s_plus_a_minus_p_semantics() {
    for kind in [
        RelocationKind::X86PcRelative32,
        RelocationKind::X86PltRelative32,
    ] {
        let mut field = [0_u8; 4];
        apply_relocation(7, &relocation(kind, -4), &mut field, 0, 0x1_000, 0x2_000).unwrap();
        assert_eq!(i32::from_le_bytes(field), 0xffc);

        apply_relocation(7, &relocation(kind, -4), &mut field, 0, 0x2_000, 0x1_000).unwrap();
        assert_eq!(i32::from_le_bytes(field), -0x1004);

        let error =
            apply_relocation(7, &relocation(kind, 0), &mut field, 0, 0, usize::MAX).unwrap_err();
        assert!(matches!(
            error,
            PublicationError::RelocationOutOfRange { index: 7, kind: actual }
                if actual == kind
        ));

        let error =
            apply_relocation(8, &relocation(kind, 0), &mut field, usize::MAX, 0, 0).unwrap_err();
        assert!(matches!(
            error,
            PublicationError::RelocationOutOfRange { index: 8, kind: actual }
                if actual == kind
        ));
    }
}

#[test]
fn aarch64_relocations_patch_adrp_add_and_branch_immediates() {
    let mut adrp = 0x9000_0018_u32.to_le_bytes();
    apply_relocation(
        0,
        &relocation(RelocationKind::Aarch64Page21, 0),
        &mut adrp,
        0,
        0x1_000,
        0x3_010,
    )
    .unwrap();
    assert_eq!(u32::from_le_bytes(adrp), 0xd000_0018);

    let mut add = 0x9100_0318_u32.to_le_bytes();
    apply_relocation(
        1,
        &relocation(RelocationKind::Aarch64PageOff12, 0),
        &mut add,
        0,
        0x1_004,
        0x3_010,
    )
    .unwrap();
    assert_eq!(u32::from_le_bytes(add), 0x9100_4318);

    let mut branch = 0x1400_0000_u32.to_le_bytes();
    apply_relocation(
        2,
        &relocation(RelocationKind::Aarch64Branch26, 0),
        &mut branch,
        0,
        0x1_000,
        0x1_020,
    )
    .unwrap();
    assert_eq!(u32::from_le_bytes(branch), 0x1400_0008);

    let mut backwards = 0x1400_0000_u32.to_le_bytes();
    apply_relocation(
        2,
        &relocation(RelocationKind::Aarch64Branch26, 0),
        &mut backwards,
        0,
        0x1_020,
        0x1_000,
    )
    .unwrap();
    assert_eq!(u32::from_le_bytes(backwards), 0x17ff_fff8);

    let error = apply_relocation(
        3,
        &relocation(RelocationKind::Aarch64Branch26, 0),
        &mut branch,
        0,
        0,
        1_usize << 28,
    )
    .unwrap_err();
    assert!(matches!(
        error,
        PublicationError::RelocationOutOfRange {
            index: 3,
            kind: RelocationKind::Aarch64Branch26,
        }
    ));

    for (word, kind) in [
        (0x1100_0318_u32, RelocationKind::Aarch64PageOff12),
        (0x9140_0318_u32, RelocationKind::Aarch64PageOff12),
        (0x9400_0000_u32, RelocationKind::Aarch64Branch26),
    ] {
        let mut bytes = word.to_le_bytes();
        assert!(matches!(
            apply_relocation(4, &relocation(kind, 0), &mut bytes, 0, 0x1_000, 0x1_020,),
            Err(PublicationError::InvalidModule { .. })
        ));
    }

    let mut unaligned = 0x1400_0000_u32.to_le_bytes();
    assert!(matches!(
        apply_relocation(
            5,
            &relocation(RelocationKind::Aarch64Branch26, 0),
            &mut unaligned,
            0,
            0x1_000,
            0x1_022,
        ),
        Err(PublicationError::RelocationOutOfRange {
            index: 5,
            kind: RelocationKind::Aarch64Branch26,
        })
    ));
}

#[test]
fn invalid_windows_are_rejected_without_entering_native_code() {
    let _lock = PUBLICATION_TEST_LOCK.lock().unwrap();
    let compiled = compile_span("needle");
    let published = publish_span(compiled, PublicationLimits::default()).unwrap();
    assert_eq!(
        published.search(b"abc", SearchWindow::new(2, 1)),
        Err(CallError::InvalidWindow {
            start: 2,
            end: 1,
            haystack_len: 3,
        })
    );
    assert!(matches!(
        published.find_at(b"abc", 4),
        Err(CallError::InvalidWindow {
            start: 4,
            end: 3,
            haystack_len: 3,
        })
    ));
}

#[cfg(all(target_arch = "aarch64", target_os = "linux"))]
mod exact_finite_selected_end_teddy_linux_aarch64_qualification {
    use std::{collections::BTreeMap, fmt::Write as _};

    use fre_aot_regex::{
        Architecture, CallAbi, CompiledRegex, CpuFeature, ExactFiniteSelectedEndTeddyAotIsa,
        ExactFiniteSelectedEndTeddyAotReport, ExactFiniteSelectedEndTeddyAotTargetTier, FeatureSet,
        OperatingSystem, SectionKind, StartAccelerator, Target,
    };

    use super::*;

    const SCANNER_FREE_BYTES: [u8; 17] = [
        0x00, 0x12, 0x3f, 0x51, 0x7e, 0x8a, 0x92, 0xa4, 0x0c, 0x18, 0x1e, 0x58, 0x5e, 0x8f, 0x98,
        0x9e, 0xaa,
    ];
    const QUALIFICATION_SEPARATOR: u8 = 0xff;
    const COLLISION_BLOCK_BYTES: usize = 32;
    const COLLISION_OFFSET: usize = 8;
    const VERIFICATION_BOUNDARIES: [usize; 3] = [63, 64, 65];

    #[derive(Clone, Copy, Debug, Eq, PartialEq)]
    enum QualificationProfile {
        Auto,
        Asimd,
        Sve,
        Sve2,
    }

    impl QualificationProfile {
        fn from_environment() -> Self {
            match std::env::var("FRE_TEDDY_PROFILE")
                .expect("FRE_TEDDY_PROFILE=auto|asimd|sve|sve2 is required")
                .as_str()
            {
                "auto" => Self::Auto,
                "asimd" => Self::Asimd,
                "sve" => Self::Sve,
                "sve2" => Self::Sve2,
                profile => panic!(
                    "unsupported FRE_TEDDY_PROFILE={profile:?}; expected auto|asimd|sve|sve2"
                ),
            }
        }

        fn target_and_receipt(
            self,
            detected: Target,
        ) -> (
            Target,
            ExactFiniteSelectedEndTeddyAotTargetTier,
            ExactFiniteSelectedEndTeddyAotIsa,
        ) {
            assert_eq!(detected.architecture, Architecture::Aarch64);
            assert_eq!(detected.operating_system, OperatingSystem::Linux);
            assert_eq!(detected.abi, CallAbi::Aapcs64);
            match self {
                Self::Auto => {
                    let required = FeatureSet::of(CpuFeature::Aarch64Asimd)
                        .with(CpuFeature::Aarch64Sve)
                        .with(CpuFeature::Aarch64Sve2);
                    assert!(
                        detected.features.contains(required),
                        "auto qualification requires the c9g ASIMD+SVE+SVE2 host: {detected:?}",
                    );
                    (
                        detected,
                        ExactFiniteSelectedEndTeddyAotTargetTier::Aarch64Sve2,
                        ExactFiniteSelectedEndTeddyAotIsa::Aarch64Sve,
                    )
                }
                Self::Asimd => (
                    Target::aarch64_linux()
                        .with_features(FeatureSet::of(CpuFeature::Aarch64Asimd))
                        .expect("exact ASIMD target"),
                    ExactFiniteSelectedEndTeddyAotTargetTier::Aarch64Asimd,
                    ExactFiniteSelectedEndTeddyAotIsa::Aarch64Asimd,
                ),
                Self::Sve => (
                    Target::aarch64_linux()
                        .with_features(FeatureSet::of(CpuFeature::Aarch64Sve))
                        .expect("exact SVE target"),
                    ExactFiniteSelectedEndTeddyAotTargetTier::Aarch64Sve,
                    ExactFiniteSelectedEndTeddyAotIsa::Aarch64Sve,
                ),
                Self::Sve2 => (
                    Target::aarch64_linux()
                        .with_features(
                            FeatureSet::of(CpuFeature::Aarch64Sve).with(CpuFeature::Aarch64Sve2),
                        )
                        .expect("exact SVE2 target"),
                    ExactFiniteSelectedEndTeddyAotTargetTier::Aarch64Sve2,
                    ExactFiniteSelectedEndTeddyAotIsa::Aarch64Sve,
                ),
            }
        }
    }

    #[derive(Clone, Copy, Debug, Eq, PartialEq)]
    struct BucketNibbles {
        low: [u16; 4],
        high: [u16; 4],
    }

    impl BucketNibbles {
        const EMPTY: Self = Self {
            low: [0; 4],
            high: [0; 4],
        };

        fn insert(&mut self, literal: &[u8], columns: usize) {
            for (column, &byte) in literal[..columns].iter().enumerate() {
                self.low[column] |= 1_u16 << u32::from(byte & 0x0f);
                self.high[column] |= 1_u16 << u32::from(byte >> 4);
            }
        }

        fn volume(self, columns: usize) -> u64 {
            (0..columns).fold(1_u64, |volume, column| {
                volume
                    .saturating_mul(u64::from(self.low[column].count_ones()))
                    .saturating_mul(u64::from(self.high[column].count_ones()))
            })
        }

        fn accepts(self, bytes: &[u8], columns: usize) -> bool {
            bytes[..columns].iter().enumerate().all(|(column, &byte)| {
                self.low[column] & (1_u16 << u32::from(byte & 0x0f)) != 0
                    && self.high[column] & (1_u16 << u32::from(byte >> 4)) != 0
            })
        }
    }

    #[derive(Clone, Debug)]
    struct CertifiedPlan {
        columns: usize,
        bucket_count: usize,
        buckets: [BucketNibbles; 8],
        assignments: Vec<u8>,
        ordinal_masks: [u64; 8],
    }

    impl CertifiedPlan {
        fn derive(literals: &[Vec<u8>], report: ExactFiniteSelectedEndTeddyAotReport) -> Self {
            let columns = usize::from(report.columns);
            let bucket_count = usize::from(report.bucket_count);
            assert!(
                (3..=4).contains(&columns),
                "unqualified columns: {report:?}"
            );
            assert!(
                (1..=8).contains(&bucket_count),
                "unqualified buckets: {report:?}"
            );
            assert_eq!(usize::from(report.literal_count), literals.len());
            assert_eq!(
                usize::try_from(report.source_count).unwrap(),
                literals.len()
            );
            assert!(literals.iter().all(|literal| literal.len() >= columns));

            let mut buckets = [BucketNibbles::EMPTY; 8];
            let mut assignments = Vec::with_capacity(literals.len());
            for literal in literals {
                let mut best = None;
                for (bucket_index, bucket) in buckets[..bucket_count].iter().copied().enumerate() {
                    let current_volume = bucket.volume(columns);
                    let mut next = bucket;
                    next.insert(literal, columns);
                    let next_volume = next.volume(columns);
                    let key = (
                        next_volume
                            .checked_sub(current_volume)
                            .expect("bucket volume is monotone"),
                        next_volume,
                        bucket_index,
                    );
                    if best.as_ref().is_none_or(
                        |(best_key, _): &((u64, u64, usize), BucketNibbles)| key < *best_key,
                    ) {
                        best = Some((key, next));
                    }
                }
                let ((_, _, bucket_index), next) = best.expect("nonempty bucket portfolio");
                buckets[bucket_index] = next;
                assignments.push(u8::try_from(bucket_index).unwrap());
            }

            let mut ordinal_masks = [0_u64; 8];
            for (ordinal, &bucket) in assignments.iter().enumerate() {
                ordinal_masks[usize::from(bucket)] |=
                    1_u64.checked_shl(u32::try_from(ordinal).unwrap()).unwrap();
            }
            Self {
                columns,
                bucket_count,
                buckets,
                assignments,
                ordinal_masks,
            }
        }

        fn candidate_buckets(&self, bytes: &[u8]) -> u8 {
            if bytes.len() < self.columns {
                return 0;
            }
            self.buckets[..self.bucket_count].iter().enumerate().fold(
                0_u8,
                |mask, (bucket, nibbles)| {
                    if nibbles.accepts(bytes, self.columns) {
                        mask | (1_u8 << u32::try_from(bucket).unwrap())
                    } else {
                        mask
                    }
                },
            )
        }

        fn candidate_ordinals(&self, bytes: &[u8]) -> u64 {
            let candidates = self.candidate_buckets(bytes);
            self.ordinal_masks[..self.bucket_count]
                .iter()
                .enumerate()
                .fold(0_u64, |mask, (bucket, ordinals)| {
                    if candidates & (1_u8 << u32::try_from(bucket).unwrap()) != 0 {
                        mask | ordinals
                    } else {
                        mask
                    }
                })
        }

        fn candidate_positions(&self, bytes: &[u8]) -> Vec<usize> {
            bytes
                .windows(self.columns)
                .enumerate()
                .filter_map(|(base, window)| (self.candidate_buckets(window) != 0).then_some(base))
                .collect()
        }
    }

    #[derive(Clone, Debug, Eq, PartialEq)]
    struct VerificationTrace {
        failed_ordinals: usize,
        candidate_bases: Vec<usize>,
        selected_end: Option<usize>,
    }

    fn trace_verifier(
        plan: &CertifiedPlan,
        literals: &[Vec<u8>],
        haystack: &[u8],
        window: SearchWindow,
    ) -> VerificationTrace {
        let mut failed_ordinals = 0_usize;
        let mut candidate_bases = Vec::new();
        let Some(last_base) = window.end().checked_sub(plan.columns) else {
            return VerificationTrace {
                failed_ordinals,
                candidate_bases,
                selected_end: None,
            };
        };
        if window.start() > last_base {
            return VerificationTrace {
                failed_ordinals,
                candidate_bases,
                selected_end: None,
            };
        }
        for base in window.start()..=last_base {
            let mut ordinals = plan.candidate_ordinals(&haystack[base..]);
            if ordinals == 0 {
                continue;
            }
            candidate_bases.push(base);
            while ordinals != 0 {
                let ordinal = usize::try_from(ordinals.trailing_zeros()).unwrap();
                ordinals &= ordinals - 1;
                let literal = &literals[ordinal];
                let matches = base
                    .checked_add(literal.len())
                    .filter(|&end| end <= window.end())
                    .is_some_and(|end| haystack[base..end] == literal[..]);
                if matches {
                    return VerificationTrace {
                        failed_ordinals,
                        candidate_bases,
                        selected_end: Some(base + literal.len()),
                    };
                }
                failed_ordinals += 1;
            }
        }
        VerificationTrace {
            failed_ordinals,
            candidate_bases,
            selected_end: None,
        }
    }

    fn manual_source_order_selected_end(
        literals: &[Vec<u8>],
        haystack: &[u8],
        window: SearchWindow,
    ) -> Option<usize> {
        for base in window.start()..=window.end() {
            for literal in literals {
                let Some(end) = base.checked_add(literal.len()) else {
                    continue;
                };
                if end <= window.end() && haystack.get(base..end) == Some(literal.as_slice()) {
                    return Some(end);
                }
            }
        }
        None
    }

    fn selected_end_pattern(literals: &[Vec<u8>]) -> String {
        let mut pattern = String::from("(?-u:");
        for (ordinal, literal) in literals.iter().enumerate() {
            if ordinal != 0 {
                pattern.push('|');
            }
            for byte in literal {
                write!(pattern, "\\x{byte:02x}").unwrap();
            }
        }
        pattern.push(')');
        pattern
    }

    fn base_literals() -> Vec<Vec<u8>> {
        SCANNER_FREE_BYTES
            .into_iter()
            .enumerate()
            .map(|(ordinal, byte)| vec![byte; 6 + usize::from(ordinal == 16)])
            .collect()
    }

    fn overlapping_literals(long_first: bool) -> Vec<Vec<u8>> {
        let mut literals = base_literals();
        let long = literals.pop().expect("long 0xaa arm");
        let short = vec![0xaa; 6];
        if long_first {
            literals.push(long);
            literals.push(short);
        } else {
            literals.push(short);
            literals.push(long);
        }
        literals
    }

    fn read_u32(data: &[u8], offset: usize) -> u32 {
        u32::from_le_bytes(
            data[offset..offset + 4]
                .try_into()
                .expect("complete u32 receipt field"),
        )
    }

    fn read_u64(data: &[u8], offset: usize) -> u64 {
        u64::from_le_bytes(
            data[offset..offset + 8]
                .try_into()
                .expect("complete u64 receipt field"),
        )
    }

    fn certify_plan(
        compiled: &CompiledRegex,
        literals: &[Vec<u8>],
        report: ExactFiniteSelectedEndTeddyAotReport,
    ) -> CertifiedPlan {
        let plan = CertifiedPlan::derive(literals, report);
        assert_eq!(
            report.source_bytes,
            literals.iter().map(Vec::len).sum::<usize>(),
        );
        assert_eq!(
            usize::try_from(report.minimum_width).unwrap(),
            literals.iter().map(Vec::len).min().unwrap(),
        );
        assert_eq!(
            usize::try_from(report.maximum_width).unwrap(),
            literals.iter().map(Vec::len).max().unwrap(),
        );
        assert_eq!(
            report.fingerprint_space,
            256_u64.pow(u32::try_from(plan.columns).unwrap()),
        );
        assert_eq!(
            report.candidate_fingerprint_upper_bound,
            plan.buckets[..plan.bucket_count]
                .iter()
                .copied()
                .map(|bucket| bucket.volume(plan.columns))
                .sum::<u64>()
                .min(report.fingerprint_space),
        );
        for (ordinal, literal) in literals.iter().enumerate() {
            let assigned = plan.assignments[ordinal];
            assert_ne!(
                plan.candidate_buckets(literal) & (1_u8 << u32::from(assigned)),
                0,
                "literal {ordinal} is absent from its reconstructed bucket",
            );
        }

        let data = compiled
            .module()
            .sections()
            .iter()
            .find(|section| section.kind == SectionKind::ReadOnlyData)
            .expect("canonical read-only data section")
            .bytes();
        let masks_offset = usize::try_from(report.bucket_ordinal_masks_offset).unwrap();
        for (bucket, expected) in plan.ordinal_masks.into_iter().enumerate() {
            assert_eq!(
                read_u64(data, masks_offset + bucket * 8),
                expected,
                "bucket {bucket} source-ordinal mask",
            );
        }
        let descriptors_offset = usize::try_from(report.literal_descriptors_offset).unwrap();
        for (ordinal, literal) in literals.iter().enumerate() {
            let descriptor = descriptors_offset + ordinal * 8;
            let offset = usize::try_from(read_u32(data, descriptor)).unwrap();
            let length = usize::try_from(read_u32(data, descriptor + 4)).unwrap();
            assert_eq!(length, literal.len(), "literal {ordinal} descriptor length");
            assert_eq!(
                data.get(offset..offset + length),
                Some(literal.as_slice()),
                "literal {ordinal} source-order bytes",
            );
        }
        plan
    }

    fn compile_qualified(
        literals: &[Vec<u8>],
        target: Target,
        expected_tier: ExactFiniteSelectedEndTeddyAotTargetTier,
        expected_isa: ExactFiniteSelectedEndTeddyAotIsa,
    ) -> (
        CompiledRegex,
        ExactFiniteSelectedEndTeddyAotReport,
        CertifiedPlan,
    ) {
        let compiled = compile(
            CompileRequest::new(selected_end_pattern(literals), target)
                .mode(CompileMode::Optimizing)
                .output(OutputContract::SelectedEnd),
        )
        .expect("compile qualified exact finite SelectedEnd Teddy artifact");
        assert!(
            compiled
                .module()
                .required_runtime_symbols()
                .next()
                .is_none(),
            "qualification artifact must be self-contained",
        );
        let report = compiled
            .receipt()
            .exact_finite_selected_end_teddy_aot
            .expect("exact finite SelectedEnd Teddy receipt is mandatory");
        assert_eq!(compiled.receipt().target, target);
        assert_eq!(report.target, target);
        assert_eq!(report.selected_target_tier, expected_tier);
        assert_eq!(report.emitted_isa, expected_isa);
        assert_eq!(report.guaranteed_vector_bytes, 16);
        let expected_scanner = match expected_isa {
            ExactFiniteSelectedEndTeddyAotIsa::X86Avx2 => StartAccelerator::X86Avx2,
            ExactFiniteSelectedEndTeddyAotIsa::Aarch64Asimd => StartAccelerator::Aarch64Asimd,
            ExactFiniteSelectedEndTeddyAotIsa::Aarch64Sve => StartAccelerator::Aarch64Sve,
        };
        assert_eq!(report.scanner, expected_scanner);
        assert_eq!(
            report.incumbent_complete_dfa.scanner,
            StartAccelerator::None
        );
        assert!(!report.incumbent_complete_dfa.has_accelerator);
        assert_eq!(report.runtime_verification_budget, 64);
        let plan = certify_plan(&compiled, literals, report);
        (compiled, report, plan)
    }

    fn portable_selected_end_for(
        compiled: &CompiledRegex,
        haystack: &[u8],
        window: SearchWindow,
    ) -> Option<usize> {
        match compiled
            .search(haystack, window)
            .expect("portable SelectedEnd oracle")
        {
            MatchResult::SelectedEnd(found) => found,
            other => panic!("portable compiler returned {other:?}"),
        }
    }

    fn assert_native_portable_manual(
        label: &str,
        literals: &[Vec<u8>],
        portable: &CompiledRegex,
        published: &PublishedSelectedEnd,
        haystack: &[u8],
        window: SearchWindow,
    ) {
        assert!(
            window.start() != 0,
            "{label}: qualification window is not mid-file"
        );
        let manual = manual_source_order_selected_end(literals, haystack, window);
        let portable_result = portable_selected_end_for(portable, haystack, window);
        assert_eq!(portable_result, manual, "{label}: portable/manual oracle");
        for at_right_boundary in [false, true] {
            let native = platform::with_guarded_haystack(haystack, at_right_boundary, |guarded| {
                published.search(guarded, window)
            })
            .unwrap_or_else(|errno| panic!("{label}: guarded mapping errno={errno}"))
            .unwrap_or_else(|error| panic!("{label}: native call: {error}"));
            assert_eq!(
                native, manual,
                "{label}: native/manual, right_guard={at_right_boundary}",
            );
        }
    }

    fn collision_block(prefix: &[u8]) -> Vec<u8> {
        let mut block = vec![QUALIFICATION_SEPARATOR; COLLISION_BLOCK_BYTES];
        block[COLLISION_OFFSET..COLLISION_OFFSET + prefix.len()].copy_from_slice(prefix);
        block
    }

    fn exact_weight_composition(
        target: usize,
        candidates: &BTreeMap<usize, Vec<u8>>,
    ) -> Option<Vec<usize>> {
        let mut compositions = vec![None::<Vec<usize>>; target + 1];
        compositions[0] = Some(Vec::new());
        for total in 0..target {
            let Some(prefix) = compositions[total].clone() else {
                continue;
            };
            for &weight in candidates.keys() {
                let Some(next) = total.checked_add(weight).filter(|&next| next <= target) else {
                    continue;
                };
                if compositions[next].is_none() {
                    let mut composition = prefix.clone();
                    composition.push(weight);
                    compositions[next] = Some(composition);
                }
            }
        }
        compositions[target].clone()
    }

    fn certify_collision_material(
        plan: &CertifiedPlan,
        literals: &[Vec<u8>],
    ) -> (BTreeMap<usize, Vec<u8>>, BTreeMap<usize, Vec<usize>>) {
        assert_eq!(
            plan.candidate_buckets(&[QUALIFICATION_SEPARATOR; 4]),
            0,
            "separator must not be a Teddy candidate",
        );
        let mut actual_block = vec![QUALIFICATION_SEPARATOR; COLLISION_BLOCK_BYTES];
        actual_block[COLLISION_OFFSET..COLLISION_OFFSET + literals[0].len()]
            .copy_from_slice(&literals[0]);
        assert!(
            plan.candidate_positions(&actual_block)
                .into_iter()
                .all(|base| base >= COLLISION_OFFSET),
            "the binary match fixture has a pre-match fingerprint",
        );
        let actual_trace = trace_verifier(
            plan,
            literals,
            &actual_block,
            SearchWindow::full(&actual_block),
        );
        assert_eq!(actual_trace.failed_ordinals, 0);
        assert_eq!(
            actual_trace.selected_end,
            Some(COLLISION_OFFSET + literals[0].len()),
        );

        let combinations = SCANNER_FREE_BYTES
            .len()
            .pow(u32::try_from(plan.columns).unwrap());
        let mut candidates = BTreeMap::new();
        for mut ordinal in 0..combinations {
            let mut prefix = vec![0_u8; plan.columns];
            for byte in &mut prefix {
                *byte = SCANNER_FREE_BYTES[ordinal % SCANNER_FREE_BYTES.len()];
                ordinal /= SCANNER_FREE_BYTES.len();
            }
            if literals
                .iter()
                .any(|literal| literal[..plan.columns] == prefix[..])
            {
                continue;
            }
            let ordinal_mask = plan.candidate_ordinals(&prefix);
            let weight = usize::try_from(ordinal_mask.count_ones()).unwrap();
            if weight == 0 || candidates.contains_key(&weight) {
                continue;
            }
            let block = collision_block(&prefix);
            if plan.candidate_positions(&block) != [COLLISION_OFFSET]
                || trace_verifier(plan, literals, &block, SearchWindow::full(&block))
                    != (VerificationTrace {
                        failed_ordinals: weight,
                        candidate_bases: vec![COLLISION_OFFSET],
                        selected_end: None,
                    })
            {
                continue;
            }
            candidates.insert(weight, prefix);
            if VERIFICATION_BOUNDARIES
                .iter()
                .all(|&boundary| exact_weight_composition(boundary, &candidates).is_some())
            {
                break;
            }
        }
        let compositions = VERIFICATION_BOUNDARIES
            .into_iter()
            .map(|boundary| {
                (
                    boundary,
                    exact_weight_composition(boundary, &candidates).unwrap_or_else(|| {
                        panic!(
                            "no certified false-fingerprint composition for {boundary} exact ordinal failures: weights={:?}",
                            candidates.keys().collect::<Vec<_>>()
                        )
                    }),
                )
            })
            .collect::<BTreeMap<_, _>>();
        (candidates, compositions)
    }

    fn budget_haystack(
        literals: &[Vec<u8>],
        report: ExactFiniteSelectedEndTeddyAotReport,
        candidates: &BTreeMap<usize, Vec<u8>>,
        composition: &[usize],
    ) -> (Vec<u8>, SearchWindow) {
        let start = 19;
        let used = composition
            .len()
            .checked_mul(COLLISION_BLOCK_BYTES)
            .and_then(|bytes| bytes.checked_add(literals[0].len()))
            .expect("bounded qualification fixture");
        let window_bytes = report
            .input_floor_bytes
            .checked_add(257)
            .expect("bounded Teddy input floor")
            .max(used + 64);
        let end = start + window_bytes;
        let mut haystack = vec![QUALIFICATION_SEPARATOR; end];
        let mut cursor = start;
        for weight in composition {
            let block = collision_block(&candidates[weight]);
            haystack[cursor..cursor + block.len()].copy_from_slice(&block);
            cursor += block.len();
        }
        let match_base = end - literals[0].len();
        assert!(
            cursor < match_base,
            "budget fixture retains a separator tail"
        );
        haystack[match_base..end].copy_from_slice(&literals[0]);
        (haystack, SearchWindow::new(start, end))
    }

    fn full_to_partial_haystack(
        literals: &[Vec<u8>],
        report: ExactFiniteSelectedEndTeddyAotReport,
        plan: &CertifiedPlan,
        false_prefix: &[u8],
        vector_bytes: usize,
    ) -> (Vec<u8>, SearchWindow, usize, usize) {
        let start = 23;
        let mut window_bytes = report.input_floor_bytes.max(vector_bytes * 3);
        let desired_remainder = 8_usize.min(vector_bytes - 1).max(4);
        while (window_bytes - plan.columns + 1) % vector_bytes != desired_remainder {
            window_bytes += 1;
        }
        let end = start + window_bytes;
        let mut haystack = vec![QUALIFICATION_SEPARATOR; end];
        let block = collision_block(false_prefix);
        haystack[start..start + block.len()].copy_from_slice(&block);
        let false_base = start + COLLISION_OFFSET;
        let match_base = end - literals[0].len();
        assert!(start + block.len() < match_base);
        haystack[match_base..end].copy_from_slice(&literals[0]);
        (
            haystack,
            SearchWindow::new(start, end),
            false_base,
            match_base,
        )
    }

    #[test]
    #[ignore = "requires Linux/AArch64 c9g hardware and FRE_TEDDY_PROFILE/FRE_EXPECTED_SVE_VL qualification receipts"]
    fn direct_loader_qualifies_exact_finite_selected_end_teddy_profiles() {
        let _lock = PUBLICATION_TEST_LOCK.lock().unwrap();
        let profile = QualificationProfile::from_environment();
        let expected_vl = std::env::var("FRE_EXPECTED_SVE_VL")
            .expect("FRE_EXPECTED_SVE_VL=<bytes> is required")
            .parse::<u16>()
            .expect("FRE_EXPECTED_SVE_VL must be a decimal u16 byte count");
        assert!((16..=256).contains(&expected_vl) && expected_vl.is_multiple_of(16));
        let observed_vl = current_thread_sve_vector_length_bytes()
            .expect("PR_SVE_GET_VL must succeed")
            .expect("the c9g qualification host must expose an SVE VL");
        assert_eq!(
            observed_vl, expected_vl,
            "exact current-thread SVE VL receipt"
        );

        let detected = host_target().expect("supported Linux/AArch64 host");
        let (target, expected_tier, expected_isa) = profile.target_and_receipt(detected);
        let literals = base_literals();
        let (compiled, report, plan) =
            compile_qualified(&literals, target, expected_tier, expected_isa);
        if profile == QualificationProfile::Asimd {
            assert!(
                !target
                    .features
                    .contains(FeatureSet::of(CpuFeature::Aarch64Sve)),
                "ASIMD qualification must remain independent of the observed SVE VL",
            );
            assert_eq!(
                report.emitted_isa,
                ExactFiniteSelectedEndTeddyAotIsa::Aarch64Asimd
            );
        } else {
            assert!(
                target
                    .features
                    .contains(FeatureSet::of(CpuFeature::Aarch64Sve)),
            );
            assert_eq!(
                report.emitted_isa,
                ExactFiniteSelectedEndTeddyAotIsa::Aarch64Sve
            );
        }
        let (candidates, compositions) = certify_collision_material(&plan, &literals);
        let portable = compiled.clone();
        let published = publish_selected_end(compiled, PublicationLimits::default())
            .expect("publish exact finite SelectedEnd Teddy without an external linker");
        assert_eq!(published.target(), target);

        for boundary in VERIFICATION_BOUNDARIES {
            let composition = &compositions[&boundary];
            let (haystack, window) = budget_haystack(&literals, report, &candidates, composition);
            let trace = trace_verifier(&plan, &literals, &haystack, window);
            assert_eq!(
                trace.failed_ordinals, boundary,
                "certified exact-verification boundary {boundary}",
            );
            assert_eq!(trace.selected_end, Some(window.end()));
            assert_native_portable_manual(
                &format!("exact-ordinal-budget-{boundary}"),
                &literals,
                &portable,
                &published,
                &haystack,
                window,
            );
        }

        let (&false_weight, false_prefix) = candidates
            .first_key_value()
            .expect("at least one certified false fingerprint");
        let (haystack, window, false_base, match_base) = full_to_partial_haystack(
            &literals,
            report,
            &plan,
            false_prefix,
            usize::from(observed_vl),
        );
        let trace = trace_verifier(&plan, &literals, &haystack, window);
        assert_eq!(trace.failed_ordinals, false_weight);
        assert_eq!(trace.candidate_bases.first(), Some(&false_base));
        assert_eq!(trace.selected_end, Some(window.end()));
        if report.emitted_isa == ExactFiniteSelectedEndTeddyAotIsa::Aarch64Sve {
            let vector_bytes = usize::from(observed_vl);
            let initial_candidate_count = window.end() - window.start() - plan.columns + 1;
            assert!(initial_candidate_count >= vector_bytes);
            assert!(false_base < window.start() + usize::from(observed_vl));
            let retry_start = false_base + 1;
            let retry_candidate_count = window.end() - retry_start - plan.columns + 1;
            let retry_full_batches = retry_candidate_count / vector_bytes;
            let retry_partial_start = retry_start + retry_full_batches * vector_bytes;
            assert!(retry_full_batches != 0);
            assert!(retry_candidate_count % vector_bytes != 0);
            assert!(match_base >= retry_partial_start);
        }
        assert_native_portable_manual(
            "false-full-batch-to-binary-eof-partial-batch",
            &literals,
            &portable,
            &published,
            &haystack,
            window,
        );

        let short_start = 7;
        let short_window_bytes = 64_usize.min(report.input_floor_bytes - 1);
        let short_end = short_start + short_window_bytes;
        let mut short = vec![QUALIFICATION_SEPARATOR; short_end];
        short[short_end - literals[0].len()..].copy_from_slice(&literals[0]);
        assert!(short_window_bytes < report.input_floor_bytes);
        assert_native_portable_manual(
            "short-incumbent-bypass-binary-eof",
            &literals,
            &portable,
            &published,
            &short,
            SearchWindow::new(short_start, short_end),
        );
        let mut short_miss = short;
        short_miss[short_end - 1] = 0x80;
        assert_native_portable_manual(
            "short-incumbent-bypass-miss",
            &literals,
            &portable,
            &published,
            &short_miss,
            SearchWindow::new(short_start, short_end),
        );

        for long_first in [false, true] {
            let ordered = overlapping_literals(long_first);
            let (compiled, ordered_report, _) =
                compile_qualified(&ordered, target, expected_tier, expected_isa);
            let portable = compiled.clone();
            let published = publish_selected_end(compiled, PublicationLimits::default())
                .expect("publish source-order overlap fixture");
            let start = 29;
            let end = start + ordered_report.input_floor_bytes + 97;
            let mut haystack = vec![QUALIFICATION_SEPARATOR; end];
            haystack[end - 7..].fill(0xaa);
            assert_native_portable_manual(
                if long_first {
                    "long-arm-before-short-arm"
                } else {
                    "short-arm-before-long-arm"
                },
                &ordered,
                &portable,
                &published,
                &haystack,
                SearchWindow::new(start, end),
            );
        }
    }
}
