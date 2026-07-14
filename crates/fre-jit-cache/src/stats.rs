//! Exact event totals and current/peak charged usage snapshots.

/// Monotonic cache event totals.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct CacheTotals {
    pub hits: u128,
    pub misses: u128,
    pub wait_events: u128,
    pub builds_started: u128,
    pub builds_succeeded: u128,
    pub build_failures: u128,
    pub build_panics: u128,
    pub evictions: u128,
    pub refusals: u128,
}

/// Current or peak cache resource usage.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct CacheUsage {
    pub entries: u64,
    pub reserved_entries: u64,
    pub in_flight_builds: u64,
    pub waiters: u64,
    pub live_mappings: u64,
    pub mapped_bytes: u64,
    pub code_bytes: u64,
    pub data_bytes: u64,
    /// Fixed policy reservation, not allocator metadata or executable pages.
    pub bookkeeping_bytes: u64,
}

/// Atomic-under-the-cache-lock diagnostic snapshot.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct CacheSnapshot {
    pub totals: CacheTotals,
    pub current: CacheUsage,
    pub peak: CacheUsage,
    pub accounting_consistent: bool,
}
