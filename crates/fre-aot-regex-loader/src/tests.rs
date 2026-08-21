use std::{io, ptr, sync::Mutex};

use fre_aot_regex::{CompileMode, CompileRequest, MatchResult, OutputContract, compile};

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
