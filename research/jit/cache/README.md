# Bounded native-kernel cache

`fre-jit-cache` is a standalone, process-local cache over the typed
`fre-jit-runtime` API. It does not emit code, allocate executable memory,
change page permissions, invoke raw function pointers, or unmap mappings.
Those responsibilities remain entirely in the runtime.

This work makes no speed claim. The evidence here covers boundedness,
concurrency, lifecycle, and accounting behavior.

## Identity and operation contract

`KernelCache<O>` is monomorphic over a sealed runtime operation. The emitter
computes the complete canonical AOT SHA-256 once, charges that work to bounded
emission, stores it in immutable `NativeImage`, and proves it equals the
serialized AOT identity. Cache lookup copies that identity in O(1), with no
serialization, rehash, scratch, or allocation. Executable publication still
independently audits the full selected image. A custom builder cannot change
the selected image, target, ABI, backend, features, source identity,
code/data/layout, or output contract unnoticed: the returned
`PublishedKernel<O>` must have the exact requested identity before admission.

`CachePolicyIdentity<O>` records policy version 1, bookkeeping model version
1, deterministic LRU-v1 eviction, all aggregate cache limits, and the fixed
per-publication runtime limits. Its generic type is part of the output
contract; caches for `Exists`, `SelectedEnd`, and `Span` cannot exchange
kernels.

## Concurrency and lifecycle

The cache uses one short state lock and a condition variable. It never holds
that lock while auditing identity, executing a builder, publishing executable
memory, invoking native code, dropping an evicted kernel, or performing the
runtime's final unmap. Poisoned locks are recovered without a panic escaping
the safe cache API.

Only one flight for a complete identity may exist. Same-key callers wait and
different keys may build concurrently up to `max_in_flight_builds`. A panic or
typed builder failure removes its flight and wakes every waiter. A same-thread
same-key reentrant request is refused rather than deadlocking. Builder results
are published into cache state once, after identity, per-publication, and
aggregate checks.

Panic cleanup applies when Rust unwinding is enabled. The workspace release
profile uses `panic = "abort"`; an aborting builder terminates the process and
cannot be converted into a cache error. No unwind crosses the safe cache API.

Resident eviction is deterministic: lowest last-use sequence first, then
lexicographically lowest complete identity. Entry-capacity eviction may remove
a resident entry that still has caller leases; those leases remain callable.
Resource-reclamation eviction selects only cache-only mappings, because
evicting a leased mapping cannot reduce live resource use.

A weak live registry prevents a lease-only evicted mapping from being
republished under the same identity. When the final lease reaches zero, a dead
weak record acts as a retirement flight: lookups wait until the destructor
removes the record by its unique mapping token and wakes them. This prevents a
queued destructor from deleting a newer same-identity record.

## Resource contract

The constructor checks and fallibly reserves bounded vectors for resident
entries, build flights, and live weak records. The stable bookkeeping model
charges 1,024 base bytes, 96 bytes per configured entry, 96 bytes per configured
flight, and 256 bytes per configured live mapping. Tests verify each charge is
at least the corresponding Rust structural payload plus Arc headers. This conservative policy
reservation is reported as current and peak bookkeeping. It excludes allocator
metadata, stack frames, and executable pages; executable pages have their own
exact runtime accounting.

Every admitted mapping is charged until the last cache/lease reference to its
tracked object is gone, even after resident eviction. Admission uses the
runtime's exact `PublicationAccounting` for live mappings, total mapped bytes,
code bytes, and data bytes. A candidate that would exceed any aggregate limit
is dropped and returned as a refusal; counters never pretend it was admitted.
Runtime publication itself occurs before aggregate admission and is bounded by
the in-flight count plus the fixed per-publication code/data/payload/mapped/page
limits.

Statistics are atomic under the state lock:

- `hits` counts requests satisfied without a build; a post-wait publication is
  still the original request's miss.
- `misses` counts each request at most once.
- `wait_events` counts actual condition-variable waits, including a repeated
  wait after a spurious wake or failed flight.
- build start/success/failure/panic, eviction, and refusal totals are monotonic
  `u128` values.
- current and peak entry reservations, flights, waiters, admitted live
  mappings, and exact mapped/code/data bytes are reported separately.
- `accounting_consistent` becomes false if an internal decrement/token
  invariant is ever violated instead of panicking from a destructor.

## Evidence and limitations

`cargo test -p fre-jit-cache` exercises high-contention same-key publication,
different-key concurrent publication, deterministic LRU order and tie-break,
outstanding leases across eviction and cache destruction, a forced dead-weak
retirement race, exact and one-below mapped-byte boundaries, current/peak
accounting, typed failure and injected panic recovery, builder-policy mismatch,
reentrant refusal, poisoned-lock recovery, identity equality, and actual
AArch64 native calls on the host.

[`scaling.csv`](scaling.csv) is generated by
`cargo run -p fre-jit-cache --example policy_scaling` and records only the
stable bookkeeping formula. [`qualification.tsv`](qualification.tsv) records
the host/gates used for this checkpoint.

Known limitations: this is not a global process cache and has no multi-process
coordination or fork protocol. It has no disk AOT cache or serialization
policy. Allocation metadata and allocator/OOM behavior are outside the stable
bookkeeping model. Statistics are per cache instance and are not persisted.
The runtime has no x86 publisher yet; actual native qualification is currently
macOS AArch64 strict-W^X only. Generated-code signals/faults remain outside the
runtime recovery contract.
