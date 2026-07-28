use std::sync::Mutex;

use fre_jit_aarch64::SELECTED_END_REGISTER_CALL_ABI_SCHEMA_V2;
use fre_jit_runtime::PublicationLimits;
use fre_kernel_ir::Span;

use crate::{
    CacheCreateError, CacheLimits, CacheResource, KernelCache, SelectedEndRegisterCacheV2,
    cache::{
        bookkeeping_structural_sizes_for_test, selected_end_bookkeeping_structural_sizes_for_test,
    },
    policy::{
        BASE_BOOKKEEPING_BYTES, ENTRY_BOOKKEEPING_BYTES, FLIGHT_BOOKKEEPING_BYTES,
        LIVE_MAPPING_BOOKKEEPING_BYTES, SELECTED_END_REGISTER_LIVE_MAPPING_BOOKKEEPING_BYTES_V2,
    },
};

#[test]
fn tracked_drop_unmaps_before_releasing_accounting_or_waiters() {
    let source = include_str!("cache.rs");
    let start = source
        .find("impl<C: CacheContract> Drop for TrackedKernel<C> {")
        .expect("tracked drop implementation");
    let length = source[start..]
        .find("\n#[derive(Clone, Copy)]\nenum Failure")
        .expect("tracked drop implementation end");
    let end = start.checked_add(length).expect("bounded source position");
    let drop_impl = &source[start..end];
    let take = drop_impl
        .find(".publication\n            .take()")
        .expect("linear publication take");
    let unmap = drop_impl
        .find("drop(publication);")
        .expect("synchronous publication drop");
    let release = drop_impl
        .find("state.remove_live(identity, self.token, accounting);")
        .expect("live accounting release");
    let wake = drop_impl
        .find("owner.wake.notify_all();")
        .expect("retirement wake");
    assert!(take < unmap);
    assert!(unmap < release);
    assert!(release < wake);
}

#[test]
fn bookkeeping_reservation_accepts_exact_and_rejects_one_below() {
    let (base, entry, flight, live) = bookkeeping_structural_sizes_for_test::<Span>();
    assert!(u64::try_from(base).expect("u64") <= BASE_BOOKKEEPING_BYTES);
    assert!(u64::try_from(entry).expect("u64") <= ENTRY_BOOKKEEPING_BYTES);
    assert!(u64::try_from(flight).expect("u64") <= FLIGHT_BOOKKEEPING_BYTES);
    assert!(u64::try_from(live).expect("u64") <= LIVE_MAPPING_BOOKKEEPING_BYTES);
    let mut limits = CacheLimits {
        max_entries: 7,
        max_in_flight_builds: 3,
        max_live_mappings: 11,
        ..CacheLimits::default()
    };
    let exact = limits
        .required_bookkeeping_bytes()
        .expect("bounded bookkeeping");
    limits.max_bookkeeping_bytes = exact;
    let cache =
        KernelCache::<Span>::new(limits, PublicationLimits::default()).expect("exact boundary");
    assert_eq!(cache.snapshot().current.bookkeeping_bytes, exact);
    assert_eq!(cache.snapshot().peak.bookkeeping_bytes, exact);

    limits.max_bookkeeping_bytes = exact.checked_sub(1).expect("nonzero bookkeeping");
    assert_eq!(
        KernelCache::<Span>::new(limits, PublicationLimits::default()).expect_err("one below"),
        CacheCreateError::ResourceLimit {
            resource: CacheResource::BookkeepingBytes,
            limit: exact.checked_sub(1).expect("nonzero bookkeeping"),
            required: exact,
        }
    );
}

#[test]
fn selected_end_abi2_cache_has_distinct_policy_and_bounded_bookkeeping() {
    let (base, entry, flight, live) = selected_end_bookkeeping_structural_sizes_for_test();
    assert!(u64::try_from(base).expect("u64") <= BASE_BOOKKEEPING_BYTES);
    assert!(u64::try_from(entry).expect("u64") <= ENTRY_BOOKKEEPING_BYTES);
    assert!(u64::try_from(flight).expect("u64") <= FLIGHT_BOOKKEEPING_BYTES);
    assert!(
        u64::try_from(live).expect("u64")
            <= SELECTED_END_REGISTER_LIVE_MAPPING_BOOKKEEPING_BYTES_V2
    );

    let mut limits = CacheLimits {
        max_entries: 7,
        max_in_flight_builds: 3,
        max_live_mappings: 11,
        ..CacheLimits::default()
    };
    let exact = limits
        .required_selected_end_register_bookkeeping_bytes_v2()
        .expect("bounded bookkeeping");
    limits.max_bookkeeping_bytes = exact;
    let publication_limits = PublicationLimits::default();
    let cache = SelectedEndRegisterCacheV2::new(limits, publication_limits)
        .expect("exact ABI2 cache boundary");
    let policy = cache.policy_identity();
    assert_eq!(
        policy.call_abi_schema,
        SELECTED_END_REGISTER_CALL_ABI_SCHEMA_V2
    );
    assert_eq!(policy.compile_key_schema, 1);
    assert_eq!(policy.cache_limits, limits);
    assert_eq!(policy.publication_limits, publication_limits);
    assert_eq!(cache.snapshot().current.bookkeeping_bytes, exact);

    limits.max_bookkeeping_bytes = exact.checked_sub(1).expect("nonzero bookkeeping");
    assert_eq!(
        SelectedEndRegisterCacheV2::new(limits, publication_limits)
            .expect_err("one below must refuse"),
        CacheCreateError::ResourceLimit {
            resource: CacheResource::BookkeepingBytes,
            limit: exact - 1,
            required: exact,
        }
    );
}

#[test]
fn poisoned_state_lock_does_not_escape_safe_api() {
    let cache = KernelCache::<Span>::new(CacheLimits::default(), PublicationLimits::default())
        .expect("cache");
    let poison = cache.clone();
    assert!(
        std::thread::spawn(move || {
            poison.poison_state_lock_for_test();
        })
        .join()
        .is_err()
    );
    let snapshot = cache.snapshot();
    assert!(snapshot.accounting_consistent);
}

#[test]
fn backend_policy_is_part_of_the_complete_cache_key() {
    use fre_jit_aarch64::{EmitLimits, SearchBackendPolicy, emit_with_backend};
    use fre_jit_runtime::RuntimeIdentity;
    use fre_kernel_ir::{AnchorFlags, ValidateLimits, build_exact_literal};

    let program = build_exact_literal::<Span>(
        b"0123456789abcdef",
        AnchorFlags::default(),
        ValidateLimits::default(),
    )
    .expect("cache-key program");
    let images = [
        SearchBackendPolicy::AsimdV7,
        SearchBackendPolicy::Sve16,
        SearchBackendPolicy::Sve2Fixed16,
    ]
    .map(|backend| {
        emit_with_backend(&program, backend, EmitLimits::default()).expect("backend-specific image")
    });
    assert_eq!(images[0].source_identity(), images[1].source_identity());
    assert_eq!(images[0].source_identity(), images[2].source_identity());

    let keys = images.each_ref().map(RuntimeIdentity::for_image);
    assert_ne!(keys[0], keys[1]);
    assert_ne!(keys[0], keys[2]);
    assert_ne!(keys[1], keys[2]);
}

#[test]
fn selected_end_abi2_cache_key_covers_backend_and_exact_literal() {
    use fre_jit_aarch64::{EmitLimits, SelectedEndRegisterBackendV2};
    use fre_kernel_ir::{AnchorFlags, ValidateLimits};

    let validation = ValidateLimits::default();
    let emission = EmitLimits::default();
    let backends = [
        SelectedEndRegisterBackendV2::AsimdV8,
        SelectedEndRegisterBackendV2::Sve16V6Tag19Vl16,
        SelectedEndRegisterBackendV2::Sve2Fixed16Tag21Vl16,
    ];
    let identities = backends.map(|backend| {
        SelectedEndRegisterCacheV2::compile_identity(
            b"0123456789abcdef",
            AnchorFlags::default(),
            backend,
            validation,
            emission,
        )
        .expect("backend-specific ABI2 compile identity")
    });
    assert_ne!(identities[0], identities[1]);
    assert_ne!(identities[0], identities[2]);
    assert_ne!(identities[1], identities[2]);

    let different_literal = SelectedEndRegisterCacheV2::compile_identity(
        b"fedcba9876543210",
        AnchorFlags::default(),
        SelectedEndRegisterBackendV2::AsimdV8,
        validation,
        emission,
    )
    .expect("different-literal ABI2 compile identity");
    assert_ne!(identities[0], different_literal);

    let mut strict_validation = validation;
    strict_validation.max_validation_work = strict_validation
        .max_validation_work
        .checked_sub(1)
        .expect("nonzero default validation work");
    let different_validation = SelectedEndRegisterCacheV2::compile_identity(
        b"0123456789abcdef",
        AnchorFlags::default(),
        SelectedEndRegisterBackendV2::AsimdV8,
        strict_validation,
        emission,
    )
    .expect("different-validation ABI2 compile identity");
    assert_ne!(identities[0], different_validation);

    let mut strict_emission = emission;
    strict_emission.max_emission_work = strict_emission
        .max_emission_work
        .checked_sub(1)
        .expect("nonzero default emission work");
    let different_emission = SelectedEndRegisterCacheV2::compile_identity(
        b"0123456789abcdef",
        AnchorFlags::default(),
        SelectedEndRegisterBackendV2::AsimdV8,
        validation,
        strict_emission,
    )
    .expect("different-emission ABI2 compile identity");
    assert_ne!(identities[0], different_emission);

    let anchored = SelectedEndRegisterCacheV2::compile_identity(
        b"0123456789abcdef",
        AnchorFlags {
            start: true,
            end: false,
        },
        SelectedEndRegisterBackendV2::AsimdV8,
        validation,
        emission,
    )
    .expect("anchored ABI2 compile identity");
    assert_ne!(identities[0], anchored);
}

#[test]
fn selected_end_abi2_compile_identity_schema_one_has_a_golden_vector() {
    use fre_jit_aarch64::{EmitLimits, SelectedEndRegisterBackendV2};
    use fre_kernel_ir::{AnchorFlags, ValidateLimits};

    let identity = SelectedEndRegisterCacheV2::compile_identity(
        b"0123456789abcdef",
        AnchorFlags::default(),
        SelectedEndRegisterBackendV2::AsimdV8,
        ValidateLimits::default(),
        EmitLimits::default(),
    )
    .expect("golden ABI2 compile identity");
    assert_eq!(
        identity.as_bytes(),
        &[
            0xf1, 0xb4, 0xa8, 0xfb, 0xb8, 0x78, 0x5f, 0xf4, 0x4a, 0xcb, 0xf8, 0x7d, 0x7b, 0x17,
            0xf3, 0x73, 0x0b, 0x67, 0xbd, 0x4e, 0x81, 0x15, 0x5d, 0x2b, 0xb9, 0x3b, 0x64, 0x3f,
            0x8d, 0x89, 0x04, 0x8d,
        ]
    );
}

#[cfg(all(
    target_arch = "aarch64",
    target_os = "macos",
    target_pointer_width = "64",
    target_endian = "little"
))]
mod native {
    use std::sync::{
        Arc, Condvar, MutexGuard,
        atomic::{AtomicBool, AtomicUsize, Ordering},
    };

    use fre_jit_aarch64::{EmitLimits, NativeImage, emit};
    use fre_jit_runtime::{FailureStage, PublishError, PublishedKernel, RuntimeIdentity, publish};
    use fre_kernel_ir::{AnchorFlags, SearchWindow, ValidateLimits, build_exact_literal};

    use super::*;
    use crate::{CacheError, cache::install_drop_hook};

    static NATIVE_CACHE_TEST_LOCK: Mutex<()> = Mutex::new(());

    #[test]
    fn high_contention_same_key_publishes_once_and_calls_native() {
        let _native = native_lock();
        let image = Arc::new(image(b"needle"));
        let cache = Arc::new(cache_for(8, 8, None));
        let builds = Arc::new(AtomicUsize::new(0));
        let released = Arc::new((Mutex::new(false), Condvar::new()));
        let start = Arc::new(std::sync::Barrier::new(17));
        let mut workers = Vec::new();
        for _ in 0..16 {
            let image = Arc::clone(&image);
            let cache = Arc::clone(&cache);
            let builds = Arc::clone(&builds);
            let released = Arc::clone(&released);
            let start = Arc::clone(&start);
            workers.push(std::thread::spawn(move || {
                start.wait();
                cache
                    .get_or_build(&image, |source, limits| {
                        builds.fetch_add(1, Ordering::SeqCst);
                        let (lock, wake) = &*released;
                        let mut allowed = lock.lock().expect("gate");
                        while !*allowed {
                            allowed = wake.wait(allowed).expect("gate wait");
                        }
                        publish::<Span>(source, limits)
                    })
                    .expect("single-flight build")
            }));
        }
        start.wait();
        wait_until(|| cache.snapshot().current.waiters == 15);
        {
            let (lock, wake) = &*released;
            *lock.lock().expect("gate") = true;
            wake.notify_all();
        }
        for worker in workers {
            let lease = worker.join().expect("worker");
            let haystack = b"zzneedlezz";
            let result = lease
                .search(haystack, SearchWindow::new(0, haystack.len()))
                .expect("native search");
            assert_eq!(result.map(|span| (span.start(), span.end())), Some((2, 8)));
        }
        let snapshot = cache.snapshot();
        assert_eq!(builds.load(Ordering::SeqCst), 1);
        assert_eq!(snapshot.totals.builds_started, 1);
        assert_eq!(snapshot.totals.builds_succeeded, 1);
        assert_eq!(snapshot.totals.misses, 16);
        assert_eq!(snapshot.totals.wait_events, 15);
        assert_eq!(snapshot.current.in_flight_builds, 0);
        assert!(snapshot.accounting_consistent);
    }

    #[test]
    fn different_keys_publish_concurrently_with_exact_peak() {
        let _native = native_lock();
        let first_image = Arc::new(image(b"parallel-first"));
        let second_image = Arc::new(image(b"parallel-second"));
        let cache = Arc::new(cache_for(2, 2, None));
        let gate = Arc::new(std::sync::Barrier::new(3));
        let mut workers = Vec::new();
        for image in [first_image, second_image] {
            let cache = Arc::clone(&cache);
            let gate = Arc::clone(&gate);
            workers.push(std::thread::spawn(move || {
                cache.get_or_build(&image, move |source, limits| {
                    gate.wait();
                    publish::<Span>(source, limits)
                })
            }));
        }
        wait_until(|| cache.snapshot().current.in_flight_builds == 2);
        gate.wait();
        for worker in workers {
            drop(
                worker
                    .join()
                    .expect("parallel worker")
                    .expect("parallel publish"),
            );
        }
        let snapshot = cache.snapshot();
        assert_eq!(snapshot.totals.builds_started, 2);
        assert_eq!(snapshot.totals.builds_succeeded, 2);
        assert_eq!(snapshot.peak.in_flight_builds, 2);
        assert_eq!(snapshot.current.in_flight_builds, 0);
        assert_eq!(snapshot.current.entries, 2);
        assert_eq!(snapshot.current.live_mappings, 2);
    }

    #[test]
    fn eviction_with_outstanding_lease_keeps_mapping_budgeted_and_reusable() {
        let _native = native_lock();
        let first_image = image(b"first");
        let second_image = image(b"second-pattern");
        let first_accounting = accounting(&first_image);
        let second_accounting = accounting(&second_image);
        let cache = cache_for(
            1,
            2,
            Some(sum_accounting(first_accounting, second_accounting)),
        );
        let first = cache.get_or_publish(&first_image).expect("first");
        let second = cache.get_or_publish(&second_image).expect("second");
        let after_eviction = cache.snapshot();
        assert_eq!(after_eviction.totals.evictions, 1);
        assert_eq!(after_eviction.current.entries, 1);
        assert_eq!(after_eviction.current.live_mappings, 2);

        let unexpected = Arc::new(AtomicBool::new(false));
        let marker = Arc::clone(&unexpected);
        let revived = cache
            .get_or_build(&first_image, move |source, limits| {
                marker.store(true, Ordering::SeqCst);
                publish::<Span>(source, limits)
            })
            .expect("lease-only live registry hit");
        assert!(!unexpected.load(Ordering::SeqCst));
        let haystack = b"xxfirstxx";
        assert_eq!(
            revived
                .search(haystack, SearchWindow::new(0, haystack.len()))
                .expect("evicted lease call")
                .map(|span| (span.start(), span.end())),
            Some((2, 7))
        );
        drop(revived);
        drop(first);
        assert_eq!(cache.snapshot().current.live_mappings, 1);
        drop(second);
    }

    #[test]
    fn dead_weak_retirement_blocks_duplicate_same_identity_publication() {
        let _native = native_lock();
        let first_image = Arc::new(image(b"retirement-race"));
        let second_image = image(b"resident-during-retirement");
        let first_accounting = accounting(&first_image);
        let second_accounting = accounting(&second_image);
        let cache = Arc::new(cache_for(
            1,
            2,
            Some(sum_accounting(first_accounting, second_accounting)),
        ));
        let first = cache.get_or_publish(&first_image).expect("first");
        let identity = first.identity();
        let second = cache.get_or_publish(&second_image).expect("evicts first");
        let (drop_entered, drop_release) = install_drop_hook(identity);
        let dropping = std::thread::spawn(move || drop(first));
        drop_entered.wait();

        let request_cache = Arc::clone(&cache);
        let request_image = Arc::clone(&first_image);
        let request = std::thread::spawn(move || request_cache.get_or_publish(&request_image));
        wait_until(|| cache.snapshot().current.waiters == 1);
        assert_eq!(cache.snapshot().current.live_mappings, 2);
        drop_release.wait();
        dropping.join().expect("retirement drop");
        let rebuilt = request
            .join()
            .expect("request thread")
            .expect("publish after exact retirement");
        let snapshot = cache.snapshot();
        assert!(snapshot.accounting_consistent);
        assert_eq!(snapshot.current.live_mappings, 2);
        assert_eq!(snapshot.totals.builds_succeeded, 3);
        drop(rebuilt);
        drop(second);
    }

    #[test]
    fn cache_drop_leaves_outstanding_lease_callable() {
        let _native = native_lock();
        let image = image(b"outlives-cache");
        let lease = {
            let cache = cache_for(1, 1, None);
            let lease = cache.get_or_publish(&image).expect("publish");
            drop(cache);
            lease
        };
        let haystack = b"xxoutlives-cacheyy";
        assert_eq!(
            lease
                .search(haystack, SearchWindow::new(0, haystack.len()))
                .expect("lease after cache drop")
                .map(|span| (span.start(), span.end())),
            Some((2, 16))
        );
    }

    #[test]
    fn deterministic_lru_and_identity_tie_break_select_expected_resident() {
        let _native = native_lock();
        let first_image = image(b"lru-first");
        let second_image = image(b"lru-second");
        let third_image = image(b"lru-third");
        let first_identity = RuntimeIdentity::for_image(&first_image);
        let second_identity = RuntimeIdentity::for_image(&second_image);
        let third_identity = RuntimeIdentity::for_image(&third_image);

        let cache = cache_for(2, 2, None);
        drop(cache.get_or_publish(&first_image).expect("first"));
        drop(cache.get_or_publish(&second_image).expect("second"));
        drop(cache.get_or_publish(&first_image).expect("touch first"));
        drop(cache.get_or_publish(&third_image).expect("evicts second"));
        let residents = cache.resident_identities_for_test();
        assert!(residents.contains(&first_identity));
        assert!(residents.contains(&third_identity));
        assert!(!residents.contains(&second_identity));

        let tied = cache_for(2, 2, None);
        drop(tied.get_or_publish(&first_image).expect("tie first"));
        drop(tied.get_or_publish(&second_image).expect("tie second"));
        tied.equalize_recency_for_test();
        drop(tied.get_or_publish(&third_image).expect("tie eviction"));
        let lexical_first = if first_identity.as_bytes() < second_identity.as_bytes() {
            first_identity
        } else {
            second_identity
        };
        let residents = tied.resident_identities_for_test();
        assert!(!residents.contains(&lexical_first));
        assert!(residents.contains(&third_identity));
    }

    #[test]
    fn aggregate_mapped_bytes_accept_exact_and_refuse_one_below() {
        let _native = native_lock();
        let image = image(b"mapped-boundary");
        let accounting = accounting(&image);
        let exact = accounting.mapped;
        let cache = cache_for(1, 1, Some(accounting));
        let lease = cache.get_or_publish(&image).expect("exact mapped bytes");
        assert_eq!(cache.snapshot().current.mapped_bytes, exact);
        drop(lease);
        drop(cache);

        let mut below = accounting;
        below.mapped = exact.checked_sub(1).expect("guarded mapping nonzero");
        let cache = cache_for(1, 1, Some(below));
        assert!(matches!(
            cache.get_or_publish(&image),
            Err(CacheError::Refused {
                resource: CacheResource::MappedBytes,
                limit,
                required,
                ..
            }) if limit == exact - 1 && required == exact
        ));
        let snapshot = cache.snapshot();
        assert_eq!(snapshot.current.live_mappings, 0);
        assert_eq!(snapshot.current.entries, 0);
        assert_eq!(snapshot.current.in_flight_builds, 0);
        assert_eq!(snapshot.totals.refusals, 1);
    }

    #[test]
    fn builder_accounting_policy_mismatch_cleans_flight_for_retry() {
        let _native = native_lock();
        let image = image(b"accounting-mismatch");
        let published = publish::<Span>(&image, PublicationLimits::default()).expect("seed");
        let accounting = published.accounting();
        drop(published);
        let publication_limits = PublicationLimits {
            max_code_bytes: u64::try_from(accounting.code_bytes)
                .expect("u64 code")
                .checked_sub(1)
                .expect("nonempty code"),
            ..PublicationLimits::default()
        };
        let cache = KernelCache::new(CacheLimits::default(), publication_limits).expect("cache");
        for _ in 0..2 {
            assert!(matches!(
                cache.get_or_build(&image, |source, _| {
                    publish::<Span>(source, PublicationLimits::default())
                }),
                Err(CacheError::BuilderPublicationLimit {
                    resource: CacheResource::CodeBytes,
                    ..
                })
            ));
            assert_eq!(cache.snapshot().current.in_flight_builds, 0);
            assert_eq!(cache.snapshot().current.reserved_entries, 0);
        }
        let snapshot = cache.snapshot();
        assert_eq!(snapshot.totals.builds_started, 2);
        assert_eq!(snapshot.totals.build_failures, 2);
        assert!(snapshot.accounting_consistent);
    }

    #[test]
    fn internal_builder_rejects_non_linear_mapping_transfer_and_recovers() {
        let _native = native_lock();
        let image = image(b"shared-builder-mapping");
        let identity = RuntimeIdentity::for_image(&image);
        let cache = cache_for(2, 2, None);
        let escaped = Arc::new(Mutex::new(None));
        let captured = Arc::clone(&escaped);
        assert!(matches!(
            cache.get_or_build(&image, move |source, limits| {
                let kernel = publish::<Span>(source, limits)?;
                *captured.lock().expect("escape slot") = Some(kernel.clone());
                Ok(kernel)
            }),
            Err(CacheError::BuilderSharedMapping { identity: actual }) if actual == identity
        ));
        // The escaped clone is deliberately outside cache ownership. Drop it
        // before inspecting live cache resources so the assertion never
        // represents a process-live executable mapping as nonexistent.
        drop(escaped.lock().expect("escape slot").take());
        let snapshot = cache.snapshot();
        assert_eq!(snapshot.current.entries, 0);
        assert_eq!(snapshot.current.live_mappings, 0);
        assert_eq!(snapshot.current.in_flight_builds, 0);
        assert_eq!(snapshot.current.reserved_entries, 0);
        assert_eq!(snapshot.totals.build_failures, 1);
        let lease = cache
            .get_or_publish(&image)
            .expect("retry after escape drop");
        assert_eq!(lease.identity(), identity);
        assert!(lease.accounting().total_mapped_bytes > 0);
    }

    #[test]
    fn current_and_peak_bytes_are_exact_across_cache_only_eviction() {
        let _native = native_lock();
        let first_image = image(b"snapshot-first");
        let second_image = image(b"snapshot-second-longer");
        let first = accounting(&first_image);
        let second = accounting(&second_image);
        let maximum = AggregateAccounting {
            mapped: first.mapped.max(second.mapped),
            code: first.code.max(second.code),
            data: first.data.max(second.data),
        };
        let cache = cache_for(1, 1, Some(maximum));
        drop(cache.get_or_publish(&first_image).expect("first"));
        let first_snapshot = cache.snapshot();
        assert_eq!(first_snapshot.current.live_mappings, 1);
        assert_eq!(first_snapshot.current.mapped_bytes, first.mapped);
        assert_eq!(first_snapshot.current.code_bytes, first.code);
        assert_eq!(first_snapshot.current.data_bytes, first.data);
        drop(cache.get_or_publish(&first_image).expect("hit"));
        drop(
            cache
                .get_or_publish(&second_image)
                .expect("evict and publish"),
        );
        let snapshot = cache.snapshot();
        assert_eq!(snapshot.totals.hits, 1);
        assert_eq!(snapshot.totals.misses, 2);
        assert_eq!(snapshot.totals.builds_started, 2);
        assert_eq!(snapshot.totals.evictions, 1);
        assert_eq!(snapshot.current.live_mappings, 1);
        assert_eq!(snapshot.current.mapped_bytes, second.mapped);
        assert_eq!(snapshot.current.code_bytes, second.code);
        assert_eq!(snapshot.current.data_bytes, second.data);
        assert_eq!(snapshot.peak.live_mappings, 1);
        assert_eq!(snapshot.peak.mapped_bytes, first.mapped.max(second.mapped));
        assert!(snapshot.accounting_consistent);
    }

    #[test]
    fn failed_and_panicking_builds_wake_waiters_and_recover() {
        let _native = native_lock();
        let recover_image = Arc::new(image(b"recover"));
        let cache = Arc::new(cache_for(2, 2, None));
        let released = Arc::new((Mutex::new(false), Condvar::new()));

        let first_cache = Arc::clone(&cache);
        let first_image = Arc::clone(&recover_image);
        let first_gate = Arc::clone(&released);
        let first = std::thread::spawn(move || {
            first_cache.get_or_build(&first_image, move |_, _| {
                let (lock, wake) = &*first_gate;
                let mut allowed = lock.lock().expect("gate");
                while !*allowed {
                    allowed = wake.wait(allowed).expect("gate wait");
                }
                Err(PublishError::InjectedFailure {
                    stage: FailureStage::Publish,
                })
            })
        });
        wait_until(|| cache.snapshot().current.in_flight_builds == 1);
        let second_cache = Arc::clone(&cache);
        let second_image = Arc::clone(&recover_image);
        let second = std::thread::spawn(move || second_cache.get_or_publish(&second_image));
        wait_until(|| cache.snapshot().current.waiters == 1);
        {
            let (lock, wake) = &*released;
            *lock.lock().expect("gate") = true;
            wake.notify_all();
        }
        assert!(matches!(
            first.join().expect("failure worker"),
            Err(CacheError::Publish(PublishError::InjectedFailure { .. }))
        ));
        let recovered = second
            .join()
            .expect("recovery worker")
            .expect("waiter rebuilds");
        drop(recovered);

        let panic_result = cache.get_or_build(
            &recover_image,
            |_, _| -> Result<PublishedKernel<Span>, PublishError> {
                panic!("injected builder panic")
            },
        );
        // The resident recovery above is a hit, so use another identity to
        // ensure the panic closure is selected as the builder.
        assert!(panic_result.is_ok());
        let panic_image = image(b"panic-key");
        assert!(matches!(
            cache.get_or_build(
                &panic_image,
                |_, _| -> Result<PublishedKernel<Span>, PublishError> {
                    panic!("injected builder panic")
                }
            ),
            Err(CacheError::BuildPanicked)
        ));
        let recovered = cache.get_or_publish(&panic_image).expect("panic recovery");
        drop(recovered);
        let snapshot = cache.snapshot();
        assert_eq!(snapshot.totals.build_failures, 1);
        assert_eq!(snapshot.totals.build_panics, 1);
        assert_eq!(snapshot.current.in_flight_builds, 0);
        assert_eq!(snapshot.current.reserved_entries, 0);
        assert!(snapshot.accounting_consistent);
    }

    #[test]
    fn same_key_reentrant_build_is_refused_without_deadlock() {
        let _native = native_lock();
        let image = image(b"reentrant");
        let nested_image = image.clone();
        let cache = cache_for(2, 2, None);
        let nested_cache = cache.clone();
        let lease = cache
            .get_or_build(&image, move |source, limits| {
                assert!(matches!(
                    nested_cache.get_or_publish(&nested_image),
                    Err(CacheError::ReentrantBuild { .. })
                ));
                publish::<Span>(source, limits)
            })
            .expect("outer build survives reentrancy");
        drop(lease);
        assert_eq!(cache.snapshot().totals.refusals, 1);
    }

    fn image(literal: &[u8]) -> NativeImage {
        let program =
            build_exact_literal::<Span>(literal, AnchorFlags::default(), ValidateLimits::default())
                .expect("valid exact program");
        emit(&program, EmitLimits::default()).expect("emit")
    }

    fn accounting(image: &NativeImage) -> AggregateAccounting {
        let kernel = publish::<Span>(image, PublicationLimits::default()).expect("accounting seed");
        let accounting = kernel.accounting();
        let result = AggregateAccounting {
            mapped: u64::try_from(accounting.total_mapped_bytes).expect("u64"),
            code: u64::try_from(accounting.code_bytes).expect("u64"),
            data: u64::try_from(accounting.data_bytes).expect("u64"),
        };
        drop(kernel);
        result
    }

    #[derive(Clone, Copy)]
    struct AggregateAccounting {
        mapped: u64,
        code: u64,
        data: u64,
    }

    fn sum_accounting(
        left: AggregateAccounting,
        right: AggregateAccounting,
    ) -> AggregateAccounting {
        AggregateAccounting {
            mapped: left
                .mapped
                .checked_add(right.mapped)
                .expect("bounded mappings"),
            code: left.code.checked_add(right.code).expect("bounded code"),
            data: left.data.checked_add(right.data).expect("bounded data"),
        }
    }

    fn cache_for(
        entries: u64,
        live: u64,
        aggregate: Option<AggregateAccounting>,
    ) -> KernelCache<Span> {
        let aggregate = aggregate.unwrap_or(AggregateAccounting {
            mapped: 64 << 20,
            code: 16 << 20,
            data: 16 << 20,
        });
        KernelCache::new(
            CacheLimits {
                max_entries: entries,
                max_in_flight_builds: 16,
                max_live_mappings: live,
                max_mapped_bytes: aggregate.mapped,
                max_code_bytes: aggregate.code,
                max_data_bytes: aggregate.data,
                max_bookkeeping_bytes: 1 << 20,
            },
            PublicationLimits::default(),
        )
        .expect("cache")
    }

    fn native_lock() -> MutexGuard<'static, ()> {
        NATIVE_CACHE_TEST_LOCK
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
    }

    fn wait_until(mut condition: impl FnMut() -> bool) {
        for _ in 0..1_000_000 {
            if condition() {
                return;
            }
            std::thread::yield_now();
        }
        panic!("condition did not become true");
    }

    #[test]
    fn runtime_identity_for_image_is_the_published_identity() {
        let _native = native_lock();
        let image = image(b"identity");
        let identity = RuntimeIdentity::for_image(&image);
        let kernel = publish::<Span>(&image, PublicationLimits::default()).expect("publish");
        assert_eq!(identity, kernel.identity());
    }
}

#[cfg(all(
    target_arch = "aarch64",
    any(target_os = "macos", target_os = "linux"),
    target_pointer_width = "64",
    target_endian = "little"
))]
mod selected_end_native {
    use std::sync::{
        Arc, Condvar, Mutex, MutexGuard,
        atomic::{AtomicUsize, Ordering},
    };

    use fre_jit_aarch64::{CpuFeatures, EmitLimits, SelectedEndRegisterBackendV2};
    use fre_jit_runtime::PublicationLimits;
    use fre_kernel_ir::{AnchorFlags, SearchWindow, ValidateLimits};

    use super::*;
    use crate::{CacheError, SelectedEndRegisterCacheV2};

    static SELECTED_END_CACHE_TEST_LOCK: Mutex<()> = Mutex::new(());

    #[test]
    fn repeated_abi2_construction_reuses_one_mapping_and_calls_without_cache_state() {
        let _native = native_lock();
        let cache = cache();
        let first = cache
            .get_or_compile_exact_literal(
                b"needle",
                AnchorFlags::default(),
                SelectedEndRegisterBackendV2::AsimdV8,
                ValidateLimits::default(),
                EmitLimits::default(),
            )
            .expect("first ABI2 compile");
        let second = cache
            .get_or_compile_exact_literal(
                b"needle",
                AnchorFlags::default(),
                SelectedEndRegisterBackendV2::AsimdV8,
                ValidateLimits::default(),
                EmitLimits::default(),
            )
            .expect("ABI2 compile cache hit");
        assert_eq!(first.artifact_identity(), second.artifact_identity());
        assert_eq!(first.compile_identity(), second.compile_identity());
        assert_eq!(first.source_identity(), second.source_identity());
        assert_eq!(first.target().features, CpuFeatures::ASIMD);
        let snapshot_before_search = cache.snapshot();
        assert_eq!(snapshot_before_search.totals.builds_started, 1);
        assert_eq!(snapshot_before_search.totals.builds_succeeded, 1);
        assert_eq!(snapshot_before_search.totals.hits, 1);
        assert_eq!(snapshot_before_search.current.live_mappings, 1);

        let session = first
            .kernel()
            .begin_current_thread_session()
            .expect("ASIMD ABI2 session");
        let haystack = b"xxneedlexx";
        let (found, _) = session
            .search(
                haystack,
                SearchWindow::new(0, haystack.len()),
                fre_jit_runtime::LiteralSearchLimits::default(),
            )
            .expect("ABI2 cached publication call");
        assert_eq!(found.map(|span| (span.start(), span.end())), Some((2, 8)));
        assert_eq!(cache.snapshot(), snapshot_before_search);

        let anchored = cache
            .get_or_compile_exact_literal(
                b"needle",
                AnchorFlags {
                    start: true,
                    end: false,
                },
                SelectedEndRegisterBackendV2::AsimdV8,
                ValidateLimits::default(),
                EmitLimits::default(),
            )
            .expect("short anchored ABI2 compile");
        assert_eq!(anchored.target().features, CpuFeatures::NONE);
    }

    #[test]
    fn abi2_builder_must_return_the_exact_requested_artifact() {
        let _native = native_lock();
        let expected_identity = SelectedEndRegisterCacheV2::compile_identity(
            b"expected",
            AnchorFlags::default(),
            SelectedEndRegisterBackendV2::AsimdV8,
            ValidateLimits::default(),
            EmitLimits::default(),
        )
        .expect("expected compile identity");
        let actual_identity = SelectedEndRegisterCacheV2::compile_identity(
            b"different",
            AnchorFlags::default(),
            SelectedEndRegisterBackendV2::AsimdV8,
            ValidateLimits::default(),
            EmitLimits::default(),
        )
        .expect("actual compile identity");
        assert_eq!(
            cache()
                .get_or_compile_substitute_for_test(
                    b"expected",
                    b"different",
                    SelectedEndRegisterBackendV2::AsimdV8,
                    ValidateLimits::default(),
                    EmitLimits::default(),
                )
                .expect_err("wrong ABI2 compile product must be rejected"),
            CacheError::BuilderIdentityMismatch {
                expected: expected_identity,
                actual: actual_identity,
            }
        );
    }

    #[test]
    fn concurrent_same_compile_request_runs_the_compiler_once() {
        let _native = native_lock();
        let cache = Arc::new(cache());
        let builds = Arc::new(AtomicUsize::new(0));
        let released = Arc::new((Mutex::new(false), Condvar::new()));
        let start = Arc::new(std::sync::Barrier::new(9));
        let mut workers = Vec::new();
        for _ in 0..8 {
            let cache = Arc::clone(&cache);
            let builds = Arc::clone(&builds);
            let released = Arc::clone(&released);
            let start = Arc::clone(&start);
            workers.push(std::thread::spawn(move || {
                start.wait();
                cache.get_or_compile_with_hook_for_test(
                    b"single-flight",
                    SelectedEndRegisterBackendV2::AsimdV8,
                    move || {
                        builds.fetch_add(1, Ordering::SeqCst);
                        let (lock, wake) = &*released;
                        let mut allowed = lock.lock().expect("compile gate");
                        while !*allowed {
                            allowed = wake.wait(allowed).expect("compile gate wait");
                        }
                    },
                )
            }));
        }
        start.wait();
        wait_until(|| cache.snapshot().current.waiters == 7);
        {
            let (lock, wake) = &*released;
            *lock.lock().expect("compile release") = true;
            wake.notify_all();
        }
        for worker in workers {
            drop(
                worker
                    .join()
                    .expect("compile worker")
                    .expect("single-flight ABI2 compile"),
            );
        }
        assert_eq!(builds.load(Ordering::SeqCst), 1);
        let snapshot = cache.snapshot();
        assert_eq!(snapshot.totals.builds_started, 1);
        assert_eq!(snapshot.totals.builds_succeeded, 1);
        assert_eq!(snapshot.totals.misses, 8);
        assert_eq!(snapshot.totals.wait_events, 7);
    }

    fn cache() -> SelectedEndRegisterCacheV2 {
        SelectedEndRegisterCacheV2::new(
            CacheLimits {
                max_entries: 8,
                max_in_flight_builds: 4,
                max_live_mappings: 16,
                max_mapped_bytes: 64 << 20,
                max_code_bytes: 16 << 20,
                max_data_bytes: 16 << 20,
                max_bookkeeping_bytes: 1 << 20,
            },
            PublicationLimits::default(),
        )
        .expect("ABI2 cache")
    }

    fn native_lock() -> MutexGuard<'static, ()> {
        SELECTED_END_CACHE_TEST_LOCK
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
    }

    fn wait_until(mut condition: impl FnMut() -> bool) {
        for _ in 0..1_000_000 {
            if condition() {
                return;
            }
            std::thread::yield_now();
        }
        panic!("condition did not become true");
    }
}
