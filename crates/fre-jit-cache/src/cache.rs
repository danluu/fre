//! Concurrent single-flight state machine and lease lifetime tracking.

use core::{fmt, ops::Deref};
use std::{
    panic::{AssertUnwindSafe, catch_unwind},
    sync::{
        Arc, Condvar, Mutex, MutexGuard, PoisonError, Weak,
        atomic::{AtomicBool, Ordering},
    },
    thread::{self, ThreadId},
};

use fre_jit_runtime::{
    NativeImage, PublicationAccounting, PublicationLimits, PublishedKernel, RuntimeIdentity,
    RuntimeOperation, publish,
};

use crate::{
    CacheCreateError, CacheError, CacheLimits, CachePolicyIdentity, CacheResource, CacheSnapshot,
    CacheTotals, CacheUsage,
};

/// A bounded process-local cache for one compile-time output contract.
pub struct KernelCache<O: RuntimeOperation> {
    inner: Arc<Inner<O>>,
}

/// A caller-owned mapping lease that remains callable after resident eviction.
pub struct KernelLease<O: RuntimeOperation> {
    tracked: Arc<TrackedKernel<O>>,
}

struct Inner<O: RuntimeOperation> {
    state: Mutex<State<O>>,
    wake: Condvar,
    policy: CachePolicyIdentity<O>,
}

struct State<O: RuntimeOperation> {
    entries: Vec<Entry<O>>,
    flights: Vec<Flight>,
    live: Vec<LiveRecord<O>>,
    totals: CacheTotals,
    current: CacheUsage,
    peak: CacheUsage,
    clock: u128,
    generation: u128,
    accounting_consistent: bool,
}

struct Entry<O: RuntimeOperation> {
    identity: RuntimeIdentity,
    last_used: u128,
    tracked: Arc<TrackedKernel<O>>,
}

#[derive(Clone, Copy, Debug)]
struct Flight {
    identity: RuntimeIdentity,
    generation: u128,
    owner: ThreadId,
}

struct LiveRecord<O: RuntimeOperation> {
    identity: RuntimeIdentity,
    token: u128,
    tracked: Weak<TrackedKernel<O>>,
}

struct TrackedKernel<O: RuntimeOperation> {
    kernel: PublishedKernel<O>,
    owner: Weak<Inner<O>>,
    token: u128,
    accounted: AtomicBool,
}

enum Lookup<O: RuntimeOperation> {
    Hit(Arc<TrackedKernel<O>>),
    Retiring,
    Miss,
}

impl<O: RuntimeOperation> Clone for KernelCache<O> {
    fn clone(&self) -> Self {
        Self {
            inner: Arc::clone(&self.inner),
        }
    }
}

impl<O: RuntimeOperation> fmt::Debug for KernelCache<O> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("KernelCache")
            .field("policy", &self.inner.policy)
            .field("snapshot", &self.snapshot())
            .finish_non_exhaustive()
    }
}

impl<O: RuntimeOperation> Clone for KernelLease<O> {
    fn clone(&self) -> Self {
        Self {
            tracked: Arc::clone(&self.tracked),
        }
    }
}

impl<O: RuntimeOperation> fmt::Debug for KernelLease<O> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("KernelLease")
            .field("kernel", &self.tracked.kernel)
            .finish()
    }
}

impl<O: RuntimeOperation> Deref for KernelLease<O> {
    type Target = PublishedKernel<O>;

    fn deref(&self) -> &Self::Target {
        &self.tracked.kernel
    }
}

impl<O: RuntimeOperation> KernelCache<O> {
    /// Construct a cache and reserve its bounded entry/flight/registry arrays.
    pub fn new(
        limits: CacheLimits,
        publication_limits: PublicationLimits,
    ) -> Result<Self, CacheCreateError> {
        let bookkeeping = limits.required_bookkeeping_bytes()?;
        if bookkeeping > limits.max_bookkeeping_bytes {
            return Err(CacheCreateError::ResourceLimit {
                resource: CacheResource::BookkeepingBytes,
                limit: limits.max_bookkeeping_bytes,
                required: bookkeeping,
            });
        }
        let entry_capacity = capacity(limits.max_entries, CacheResource::Entries)?;
        let flight_capacity = capacity(limits.max_in_flight_builds, CacheResource::InFlightBuilds)?;
        let live_capacity = capacity(limits.max_live_mappings, CacheResource::LiveMappings)?;
        let mut entries = Vec::new();
        entries.try_reserve_exact(entry_capacity).map_err(|_| {
            CacheCreateError::AllocationFailed {
                resource: CacheResource::Entries,
                entries: limits.max_entries,
            }
        })?;
        let mut flights = Vec::new();
        flights.try_reserve_exact(flight_capacity).map_err(|_| {
            CacheCreateError::AllocationFailed {
                resource: CacheResource::InFlightBuilds,
                entries: limits.max_in_flight_builds,
            }
        })?;
        let mut live = Vec::new();
        live.try_reserve_exact(live_capacity)
            .map_err(|_| CacheCreateError::AllocationFailed {
                resource: CacheResource::LiveMappings,
                entries: limits.max_live_mappings,
            })?;
        let current = CacheUsage {
            bookkeeping_bytes: bookkeeping,
            ..CacheUsage::default()
        };
        Ok(Self {
            inner: Arc::new(Inner {
                state: Mutex::new(State {
                    entries,
                    flights,
                    live,
                    totals: CacheTotals::default(),
                    current,
                    peak: current,
                    clock: 0,
                    generation: 0,
                    accounting_consistent: true,
                }),
                wake: Condvar::new(),
                policy: CachePolicyIdentity::new(limits, publication_limits),
            }),
        })
    }

    /// Stable cache and per-publication policy identity.
    #[must_use]
    pub fn policy_identity(&self) -> CachePolicyIdentity<O> {
        self.inner.policy
    }

    /// Publish on a miss using the cache's fixed runtime publication policy.
    pub fn get_or_publish(&self, image: &NativeImage) -> Result<KernelLease<O>, CacheError> {
        self.get_or_build(image, |source, limits| publish::<O>(source, limits))
    }

    /// Look up or single-flight one caller-supplied typed publisher.
    ///
    /// The closure runs without a cache lock. Its result is admitted only when
    /// its complete runtime identity matches `image` and its exact accounting
    /// obeys both the publication and aggregate cache policies.
    #[allow(
        clippy::too_many_lines,
        reason = "the full lookup/wait/build transition is kept together so every exit visibly cleans its flight"
    )]
    pub fn get_or_build<F>(
        &self,
        image: &NativeImage,
        build: F,
    ) -> Result<KernelLease<O>, CacheError>
    where
        F: FnOnce(
            &NativeImage,
            PublicationLimits,
        ) -> Result<PublishedKernel<O>, fre_jit_runtime::PublishError>,
    {
        let identity = RuntimeIdentity::for_image(image);
        let mut build = Some(build);
        let mut classified = false;
        let generation = loop {
            let mut retired = None;
            let mut state = self.lock();
            match state.lookup(identity)? {
                Lookup::Hit(tracked) => {
                    if !classified {
                        bump(&mut state.totals.hits)?;
                    }
                    drop(state);
                    return Ok(KernelLease { tracked });
                }
                Lookup::Retiring => {
                    if !classified {
                        bump(&mut state.totals.misses)?;
                        classified = true;
                    }
                    bump(&mut state.totals.wait_events)?;
                    state.current.waiters =
                        checked_add(state.current.waiters, 1, CacheResource::Counter)?;
                    state.update_peak();
                    state = self.wait(state);
                    state.current.waiters = checked_sub_usage(
                        state.current.waiters,
                        1,
                        &mut state.accounting_consistent,
                    );
                    drop(state);
                    continue;
                }
                Lookup::Miss => {}
            }
            if !classified {
                bump(&mut state.totals.misses)?;
                classified = true;
            }
            if let Ok(index) = flight_index(&state.flights, identity) {
                if state.flights[index].owner == thread::current().id() {
                    bump(&mut state.totals.refusals)?;
                    return Err(CacheError::ReentrantBuild { identity });
                }
                bump(&mut state.totals.wait_events)?;
                state.current.waiters =
                    checked_add(state.current.waiters, 1, CacheResource::Counter)?;
                state.update_peak();
                state = self.wait(state);
                state.current.waiters =
                    checked_sub_usage(state.current.waiters, 1, &mut state.accounting_consistent);
                drop(state);
                continue;
            }
            if state.current.in_flight_builds >= self.inner.policy.cache_limits.max_in_flight_builds
            {
                let current = state.current.in_flight_builds;
                return Err(state.refusal(
                    CacheResource::InFlightBuilds,
                    self.inner.policy.cache_limits.max_in_flight_builds,
                    current,
                    1,
                )?);
            }
            let occupied = state
                .current
                .entries
                .checked_add(state.current.reserved_entries)
                .ok_or(CacheError::AccountingOverflow {
                    resource: CacheResource::Entries,
                })?;
            if occupied >= self.inner.policy.cache_limits.max_entries {
                if self.inner.policy.cache_limits.max_entries == 0 {
                    return Err(state.refusal(CacheResource::Entries, 0, occupied, 1)?);
                }
                let Some(index) = state.eviction_index(false) else {
                    return Err(state.refusal(
                        CacheResource::Entries,
                        self.inner.policy.cache_limits.max_entries,
                        occupied,
                        1,
                    )?);
                };
                retired = Some(state.remove_entry(index)?);
            }
            let next_generation =
                state
                    .generation
                    .checked_add(1)
                    .ok_or(CacheError::AccountingOverflow {
                        resource: CacheResource::Counter,
                    })?;
            bump(&mut state.totals.builds_started)?;
            let flight = Flight {
                identity,
                generation: next_generation,
                owner: thread::current().id(),
            };
            let index = state
                .flights
                .binary_search_by(|candidate| compare(candidate.identity, identity))
                .unwrap_or_else(core::convert::identity);
            state.flights.insert(index, flight);
            state.generation = next_generation;
            state.current.in_flight_builds = checked_add(
                state.current.in_flight_builds,
                1,
                CacheResource::InFlightBuilds,
            )?;
            state.current.reserved_entries =
                checked_add(state.current.reserved_entries, 1, CacheResource::Entries)?;
            state.update_peak();
            drop(state);
            drop(retired);
            break next_generation;
        };

        let builder = build.take().ok_or(CacheError::AccountingOverflow {
            resource: CacheResource::Counter,
        })?;
        let build_outcome = catch_unwind(AssertUnwindSafe(|| {
            builder(image, self.inner.policy.publication_limits)
        }));
        let kernel = match build_outcome {
            Ok(Ok(kernel)) => kernel,
            Ok(Err(error)) => {
                self.finish_failed(identity, generation, Failure::Error)?;
                return Err(CacheError::Publish(error));
            }
            Err(_) => {
                self.finish_failed(identity, generation, Failure::Panic)?;
                return Err(CacheError::BuildPanicked);
            }
        };
        if kernel.identity() != identity {
            let actual = kernel.identity();
            self.finish_failed(identity, generation, Failure::Error)?;
            return Err(CacheError::BuilderIdentityMismatch {
                expected: identity,
                actual,
            });
        }
        enforce_publication_accounting(kernel.accounting(), self.inner.policy.publication_limits)
            .inspect_err(|_| {
            let _ = self.finish_failed(identity, generation, Failure::Error);
        })?;
        self.admit(identity, generation, kernel)
    }

    /// Exact diagnostic counters and charged usage under one state lock.
    #[must_use]
    pub fn snapshot(&self) -> CacheSnapshot {
        let state = self.lock();
        CacheSnapshot {
            totals: state.totals,
            current: state.current,
            peak: state.peak,
            accounting_consistent: state.accounting_consistent,
        }
    }

    #[cfg(test)]
    pub(crate) fn poison_state_lock_for_test(&self) {
        let _guard = self
            .inner
            .state
            .lock()
            .expect("initially healthy test lock");
        panic!("intentional state poison");
    }

    #[cfg(test)]
    pub(crate) fn equalize_recency_for_test(&self) {
        let mut state = self.lock();
        for entry in &mut state.entries {
            entry.last_used = 1;
        }
    }

    #[cfg(test)]
    pub(crate) fn resident_identities_for_test(&self) -> Vec<RuntimeIdentity> {
        self.lock()
            .entries
            .iter()
            .map(|entry| entry.identity)
            .collect()
    }

    fn admit(
        &self,
        identity: RuntimeIdentity,
        generation: u128,
        kernel: PublishedKernel<O>,
    ) -> Result<KernelLease<O>, CacheError> {
        let accounting = kernel.accounting();
        let tracked = Arc::new(TrackedKernel {
            kernel,
            owner: Arc::downgrade(&self.inner),
            token: generation,
            accounted: AtomicBool::new(false),
        });
        loop {
            let mut state = self.lock();
            state.require_flight(identity, generation)?;
            if let Some(failure) =
                state.aggregate_failure(accounting, self.inner.policy.cache_limits)?
            {
                if let Some(index) = state.eviction_index(true) {
                    let retired = state.remove_entry(index)?;
                    drop(state);
                    drop(retired);
                    continue;
                }
                let error = state.refusal(
                    failure.resource,
                    failure.limit,
                    failure.current,
                    failure.required,
                )?;
                state.remove_flight(identity, generation)?;
                drop(state);
                self.inner.wake.notify_all();
                drop(tracked);
                return Err(error);
            }
            let use_sequence = state.next_clock()?;
            bump(&mut state.totals.builds_succeeded)?;
            state.add_live(accounting)?;
            tracked.accounted.store(true, Ordering::Release);
            let live_index = state
                .live
                .binary_search_by(|record| compare(record.identity, identity))
                .unwrap_or_else(core::convert::identity);
            state.live.insert(
                live_index,
                LiveRecord {
                    identity,
                    token: generation,
                    tracked: Arc::downgrade(&tracked),
                },
            );
            let entry_index = state
                .entries
                .binary_search_by(|entry| compare(entry.identity, identity))
                .unwrap_or_else(core::convert::identity);
            state.entries.insert(
                entry_index,
                Entry {
                    identity,
                    last_used: use_sequence,
                    tracked: Arc::clone(&tracked),
                },
            );
            state.current.entries = checked_add(state.current.entries, 1, CacheResource::Entries)?;
            state.remove_flight(identity, generation)?;
            state.update_peak();
            drop(state);
            self.inner.wake.notify_all();
            return Ok(KernelLease { tracked });
        }
    }

    fn finish_failed(
        &self,
        identity: RuntimeIdentity,
        generation: u128,
        failure: Failure,
    ) -> Result<(), CacheError> {
        let mut state = self.lock();
        match failure {
            Failure::Error => bump(&mut state.totals.build_failures)?,
            Failure::Panic => bump(&mut state.totals.build_panics)?,
        }
        state.remove_flight(identity, generation)?;
        drop(state);
        self.inner.wake.notify_all();
        Ok(())
    }

    fn lock(&self) -> MutexGuard<'_, State<O>> {
        self.inner
            .state
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
    }

    fn wait<'a>(&self, state: MutexGuard<'a, State<O>>) -> MutexGuard<'a, State<O>> {
        self.inner
            .wake
            .wait(state)
            .unwrap_or_else(PoisonError::into_inner)
    }
}

impl<O: RuntimeOperation> State<O> {
    fn lookup(&mut self, identity: RuntimeIdentity) -> Result<Lookup<O>, CacheError> {
        if let Ok(index) = entry_index(&self.entries, identity) {
            let sequence = self.next_clock()?;
            self.entries[index].last_used = sequence;
            return Ok(Lookup::Hit(Arc::clone(&self.entries[index].tracked)));
        }
        if let Ok(index) = live_index(&self.live, identity) {
            return Ok(match self.live[index].tracked.upgrade() {
                Some(tracked) => Lookup::Hit(tracked),
                None => Lookup::Retiring,
            });
        }
        Ok(Lookup::Miss)
    }

    fn next_clock(&mut self) -> Result<u128, CacheError> {
        let next = self
            .clock
            .checked_add(1)
            .ok_or(CacheError::AccountingOverflow {
                resource: CacheResource::Counter,
            })?;
        self.clock = next;
        Ok(next)
    }

    fn eviction_index(&self, cache_only: bool) -> Option<usize> {
        self.entries
            .iter()
            .enumerate()
            .filter(|(_, entry)| !cache_only || Arc::strong_count(&entry.tracked) == 1)
            .min_by(|(_, left), (_, right)| {
                left.last_used
                    .cmp(&right.last_used)
                    .then_with(|| compare(left.identity, right.identity))
            })
            .map(|(index, _)| index)
    }

    fn remove_entry(&mut self, index: usize) -> Result<Arc<TrackedKernel<O>>, CacheError> {
        let entry = self.entries.remove(index);
        self.current.entries =
            checked_sub_usage(self.current.entries, 1, &mut self.accounting_consistent);
        bump(&mut self.totals.evictions)?;
        Ok(entry.tracked)
    }

    fn require_flight(
        &self,
        identity: RuntimeIdentity,
        generation: u128,
    ) -> Result<(), CacheError> {
        let index =
            flight_index(&self.flights, identity).map_err(|_| CacheError::AccountingOverflow {
                resource: CacheResource::InFlightBuilds,
            })?;
        if self.flights[index].generation != generation {
            return Err(CacheError::AccountingOverflow {
                resource: CacheResource::InFlightBuilds,
            });
        }
        Ok(())
    }

    fn remove_flight(
        &mut self,
        identity: RuntimeIdentity,
        generation: u128,
    ) -> Result<(), CacheError> {
        self.require_flight(identity, generation)?;
        let index =
            flight_index(&self.flights, identity).map_err(|_| CacheError::AccountingOverflow {
                resource: CacheResource::InFlightBuilds,
            })?;
        self.flights.remove(index);
        self.current.in_flight_builds = checked_sub_usage(
            self.current.in_flight_builds,
            1,
            &mut self.accounting_consistent,
        );
        self.current.reserved_entries = checked_sub_usage(
            self.current.reserved_entries,
            1,
            &mut self.accounting_consistent,
        );
        Ok(())
    }

    fn aggregate_failure(
        &self,
        accounting: PublicationAccounting,
        limits: CacheLimits,
    ) -> Result<Option<LimitFailure>, CacheError> {
        for (resource, current, required, limit) in [
            (
                CacheResource::LiveMappings,
                self.current.live_mappings,
                1,
                limits.max_live_mappings,
            ),
            (
                CacheResource::MappedBytes,
                self.current.mapped_bytes,
                to_u64(accounting.total_mapped_bytes, CacheResource::MappedBytes)?,
                limits.max_mapped_bytes,
            ),
            (
                CacheResource::CodeBytes,
                self.current.code_bytes,
                to_u64(accounting.code_bytes, CacheResource::CodeBytes)?,
                limits.max_code_bytes,
            ),
            (
                CacheResource::DataBytes,
                self.current.data_bytes,
                to_u64(accounting.data_bytes, CacheResource::DataBytes)?,
                limits.max_data_bytes,
            ),
        ] {
            let total = current
                .checked_add(required)
                .ok_or(CacheError::AccountingOverflow { resource })?;
            if total > limit {
                return Ok(Some(LimitFailure {
                    resource,
                    limit,
                    current,
                    required,
                }));
            }
        }
        Ok(None)
    }

    fn add_live(&mut self, accounting: PublicationAccounting) -> Result<(), CacheError> {
        self.current.live_mappings =
            checked_add(self.current.live_mappings, 1, CacheResource::LiveMappings)?;
        self.current.mapped_bytes = checked_add(
            self.current.mapped_bytes,
            to_u64(accounting.total_mapped_bytes, CacheResource::MappedBytes)?,
            CacheResource::MappedBytes,
        )?;
        self.current.code_bytes = checked_add(
            self.current.code_bytes,
            to_u64(accounting.code_bytes, CacheResource::CodeBytes)?,
            CacheResource::CodeBytes,
        )?;
        self.current.data_bytes = checked_add(
            self.current.data_bytes,
            to_u64(accounting.data_bytes, CacheResource::DataBytes)?,
            CacheResource::DataBytes,
        )?;
        Ok(())
    }

    fn remove_live(
        &mut self,
        identity: RuntimeIdentity,
        token: u128,
        accounting: PublicationAccounting,
    ) {
        if let Some(index) = self
            .live
            .iter()
            .position(|record| record.identity == identity && record.token == token)
        {
            self.live.remove(index);
        } else {
            self.accounting_consistent = false;
        }
        subtract(
            &mut self.current.live_mappings,
            1,
            &mut self.accounting_consistent,
        );
        subtract(
            &mut self.current.mapped_bytes,
            u64::try_from(accounting.total_mapped_bytes).unwrap_or(u64::MAX),
            &mut self.accounting_consistent,
        );
        subtract(
            &mut self.current.code_bytes,
            u64::try_from(accounting.code_bytes).unwrap_or(u64::MAX),
            &mut self.accounting_consistent,
        );
        subtract(
            &mut self.current.data_bytes,
            u64::try_from(accounting.data_bytes).unwrap_or(u64::MAX),
            &mut self.accounting_consistent,
        );
    }

    fn refusal(
        &mut self,
        resource: CacheResource,
        limit: u64,
        current: u64,
        required: u64,
    ) -> Result<CacheError, CacheError> {
        bump(&mut self.totals.refusals)?;
        Ok(CacheError::Refused {
            resource,
            limit,
            current,
            required,
        })
    }

    fn update_peak(&mut self) {
        self.peak.entries = self.peak.entries.max(self.current.entries);
        self.peak.reserved_entries = self
            .peak
            .reserved_entries
            .max(self.current.reserved_entries);
        self.peak.in_flight_builds = self
            .peak
            .in_flight_builds
            .max(self.current.in_flight_builds);
        self.peak.waiters = self.peak.waiters.max(self.current.waiters);
        self.peak.live_mappings = self.peak.live_mappings.max(self.current.live_mappings);
        self.peak.mapped_bytes = self.peak.mapped_bytes.max(self.current.mapped_bytes);
        self.peak.code_bytes = self.peak.code_bytes.max(self.current.code_bytes);
        self.peak.data_bytes = self.peak.data_bytes.max(self.current.data_bytes);
        self.peak.bookkeeping_bytes = self
            .peak
            .bookkeeping_bytes
            .max(self.current.bookkeeping_bytes);
    }
}

impl<O: RuntimeOperation> Drop for TrackedKernel<O> {
    fn drop(&mut self) {
        if !self.accounted.load(Ordering::Acquire) {
            return;
        }
        #[cfg(test)]
        run_drop_hook(self.kernel.identity());
        if let Some(owner) = self.owner.upgrade() {
            {
                let mut state = owner.state.lock().unwrap_or_else(PoisonError::into_inner);
                state.remove_live(self.kernel.identity(), self.token, self.kernel.accounting());
            }
            owner.wake.notify_all();
            drop(owner);
        }
        // `PublishedKernel` is dropped, and may unmap, only after this method
        // has released the cache lock and the upgraded owner reference.
    }
}

#[derive(Clone, Copy)]
enum Failure {
    Error,
    Panic,
}

#[derive(Clone, Copy)]
struct LimitFailure {
    resource: CacheResource,
    limit: u64,
    current: u64,
    required: u64,
}

#[cfg(test)]
struct DropHook {
    identity: RuntimeIdentity,
    entered: Arc<std::sync::Barrier>,
    release: Arc<std::sync::Barrier>,
}

#[cfg(test)]
static DROP_HOOK: Mutex<Option<DropHook>> = Mutex::new(None);

#[cfg(test)]
pub(crate) fn install_drop_hook(
    identity: RuntimeIdentity,
) -> (Arc<std::sync::Barrier>, Arc<std::sync::Barrier>) {
    let entered = Arc::new(std::sync::Barrier::new(2));
    let release = Arc::new(std::sync::Barrier::new(2));
    let mut hook = DROP_HOOK.lock().unwrap_or_else(PoisonError::into_inner);
    assert!(hook.is_none(), "only one serialized drop hook is supported");
    *hook = Some(DropHook {
        identity,
        entered: Arc::clone(&entered),
        release: Arc::clone(&release),
    });
    (entered, release)
}

#[cfg(test)]
pub(crate) fn bookkeeping_structural_sizes_for_test<O: RuntimeOperation>()
-> (usize, usize, usize, usize) {
    let arc_header = core::mem::size_of::<usize>()
        .checked_mul(2)
        .expect("two pointer-sized Arc counters");
    (
        core::mem::size_of::<Inner<O>>()
            .checked_add(arc_header)
            .expect("bounded inner size"),
        core::mem::size_of::<Entry<O>>(),
        core::mem::size_of::<Flight>(),
        core::mem::size_of::<LiveRecord<O>>()
            .checked_add(core::mem::size_of::<TrackedKernel<O>>())
            .and_then(|bytes| bytes.checked_add(arc_header))
            .expect("bounded live structural size"),
    )
}

#[cfg(test)]
fn run_drop_hook(identity: RuntimeIdentity) {
    let barriers = {
        let mut hook = DROP_HOOK.lock().unwrap_or_else(PoisonError::into_inner);
        if hook
            .as_ref()
            .is_some_and(|candidate| candidate.identity == identity)
        {
            hook.take()
                .map(|candidate| (candidate.entered, candidate.release))
        } else {
            None
        }
    };
    if let Some((entered, release)) = barriers {
        entered.wait();
        release.wait();
    }
}

fn enforce_publication_accounting(
    accounting: PublicationAccounting,
    limits: PublicationLimits,
) -> Result<(), CacheError> {
    for (resource, required, limit) in [
        (
            CacheResource::CodeBytes,
            to_u64(accounting.code_bytes, CacheResource::CodeBytes)?,
            limits.max_code_bytes,
        ),
        (
            CacheResource::DataBytes,
            to_u64(accounting.data_bytes, CacheResource::DataBytes)?,
            limits.max_data_bytes,
        ),
        (
            CacheResource::PayloadBytes,
            to_u64(accounting.payload_mapped_bytes, CacheResource::PayloadBytes)?,
            limits.max_payload_bytes,
        ),
        (
            CacheResource::MappedBytes,
            to_u64(accounting.total_mapped_bytes, CacheResource::MappedBytes)?,
            limits.max_mapped_bytes,
        ),
        (
            CacheResource::Pages,
            to_u64(accounting.total_pages, CacheResource::Pages)?,
            limits.max_pages,
        ),
    ] {
        if required > limit {
            return Err(CacheError::BuilderPublicationLimit {
                resource,
                limit,
                required,
            });
        }
    }
    Ok(())
}

fn entry_index<O: RuntimeOperation>(
    entries: &[Entry<O>],
    identity: RuntimeIdentity,
) -> Result<usize, usize> {
    entries.binary_search_by(|entry| compare(entry.identity, identity))
}

fn flight_index(flights: &[Flight], identity: RuntimeIdentity) -> Result<usize, usize> {
    flights.binary_search_by(|flight| compare(flight.identity, identity))
}

fn live_index<O: RuntimeOperation>(
    records: &[LiveRecord<O>],
    identity: RuntimeIdentity,
) -> Result<usize, usize> {
    records.binary_search_by(|record| compare(record.identity, identity))
}

fn compare(left: RuntimeIdentity, right: RuntimeIdentity) -> core::cmp::Ordering {
    left.as_bytes().cmp(right.as_bytes())
}

fn capacity(value: u64, resource: CacheResource) -> Result<usize, CacheCreateError> {
    usize::try_from(value).map_err(|_| CacheCreateError::ResourceLimit {
        resource,
        limit: u64::try_from(usize::MAX).unwrap_or(u64::MAX),
        required: value,
    })
}

fn to_u64(value: usize, resource: CacheResource) -> Result<u64, CacheError> {
    u64::try_from(value).map_err(|_| CacheError::AccountingOverflow { resource })
}

fn bump(counter: &mut u128) -> Result<(), CacheError> {
    *counter = counter
        .checked_add(1)
        .ok_or(CacheError::AccountingOverflow {
            resource: CacheResource::Counter,
        })?;
    Ok(())
}

fn checked_add(left: u64, right: u64, resource: CacheResource) -> Result<u64, CacheError> {
    left.checked_add(right)
        .ok_or(CacheError::AccountingOverflow { resource })
}

fn checked_sub_usage(current: u64, amount: u64, consistent: &mut bool) -> u64 {
    if let Some(value) = current.checked_sub(amount) {
        value
    } else {
        *consistent = false;
        0
    }
}

fn subtract(current: &mut u64, amount: u64, consistent: &mut bool) {
    *current = checked_sub_usage(*current, amount, consistent);
}
