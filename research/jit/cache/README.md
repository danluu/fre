# Bounded native-kernel cache

`fre-jit-cache` is a standalone, process-local cache over the typed
`fre-jit-runtime` API. `KernelCache<O>` accepts an already emitted image. The
nominal ABI2 construction cache instead owns its bounded Kernel IR and
machine-code emission miss path so lookup occurs before compiler work. Neither
path changes page permissions, invokes raw function pointers, or unmaps
mappings; those responsibilities remain entirely in the runtime.

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

Register-return ABI2 uses the separate
`SelectedEndRegisterCacheV2`/`SelectedEndRegisterLeaseV2` nominal API. Its key
is `SelectedEndRegisterCompileIdentityV2`, a domain-separated digest computed
before Kernel IR construction. Its schema-1 canonical little-endian encoding
contains the exact literal, anchors, selected-end output, raw/KIR
semantics/ABI versions, register-return ABI2 schema and return encoding,
nominal backend tag and backend version, complete target/features/fixed VL,
and every field of `ValidateLimits` and `EmitLimits`. Both limits structs are
exhaustively destructured, so adding a field is a compile error until the key
schema is reviewed. A golden vector pins field order and endianness. The
eventual `SelectedEndRegisterArtifactIdentityV2` remains the authenticated
post-build receipt rather than the lookup key.

The nominal policy identity records call ABI schema 2, compile-key schema 1,
all aggregate limits, and one exact per-publication policy. A cache never
reuses a broadly published mapping for a caller asking for a different
publication policy. The miss path builds and validates exact-literal Kernel
IR, emits and checks the complete audited image against the request, then
publishes it. The runtime ABI2 publication handle is move-only, and the cache
takes that linear ownership before charging the mapping. Cache leases may be
cloned because every clone retains the cache-tracked owner; borrowing the
publication cannot create an unaccounted mapping clone. A matcher retains the
lease and borrows its immutable publication when it opens a current-thread
session, so cache locking and lease cloning are construction work rather than
repeated-search work.

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
queued destructor from deleting a newer same-identity record. Final retirement
synchronously drops and unmaps the publication while its weak record and
aggregate byte charge still block admission; only then does it release that
accounting and wake waiters.

## Resource contract

The constructor checks and fallibly reserves bounded vectors for resident
entries, build flights, and live weak records. The stable bookkeeping model
charges 1,024 base bytes, 96 bytes per configured entry, 96 bytes per configured
flight, and 256 bytes per configured live mapping. Tests verify each charge is
at least the corresponding Rust structural payload plus Arc headers. The
nominal ABI2 policy uses a separate conservative 512-byte live-mapping charge
because its tracked publication retains the source/compile receipt and exact
emission statistics in addition to the mapping. This conservative policy
reservation is reported as current and peak bookkeeping. It excludes
allocator metadata, stack frames, and executable pages; executable pages have
their own exact runtime accounting.

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

`cargo test -p fre-jit-cache` is intended to exercise high-contention same-key
publication, different-key concurrent publication, deterministic LRU order and tie-break,
outstanding leases across eviction and cache destruction, a forced dead-weak
retirement race, exact and one-below mapped-byte boundaries, current/peak
accounting, typed failure and injected panic recovery, builder-policy mismatch,
reentrant refusal, poisoned-lock recovery, identity equality, ABI2
backend/literal/limit/anchor key separation, the golden compile-key vector,
wrong-compile-product rejection, compile single-flight, construction reuse,
and actual AArch64 native calls on the host. The ABI2 additions remain
source-only until that command is allowed by the active admission fence and
the retained result is recorded.

`scaling.csv` is generated by
`cargo run -p fre-jit-cache --example policy_scaling` and records only the
stable bookkeeping formula. `qualification.tsv` records
the host/gates used for this checkpoint.

Known limitations: this is not a global process cache and has no multi-process
coordination or fork protocol. It has no disk AOT cache or serialization
policy. Allocation metadata and allocator/OOM behavior are outside the stable
bookkeeping model. Statistics are per cache instance and are not persisted.
The runtime has no x86 publisher yet. The source supports strict-W^X AArch64
macOS and Linux, but this ABI2 cache change has no retained dynamic result
under the active admission fence. Generated-code signals/faults remain
outside the runtime recovery contract.
