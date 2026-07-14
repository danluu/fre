use std::sync::Mutex;

use fre_jit_runtime::PublicationLimits;
use fre_kernel_ir::Span;

use crate::{
    CacheCreateError, CacheLimits, CacheResource, KernelCache,
    cache::bookkeeping_structural_sizes_for_test,
    policy::{
        BASE_BOOKKEEPING_BYTES, ENTRY_BOOKKEEPING_BYTES, FLIGHT_BOOKKEEPING_BYTES,
        LIVE_MAPPING_BOOKKEEPING_BYTES,
    },
};

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
