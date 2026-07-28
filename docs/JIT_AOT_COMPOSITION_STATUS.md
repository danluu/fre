# JIT/AOT composition status

Last updated: 2026-07-27 (America/Vancouver)

This source composes the reviewed current JIT/VL16 line and the path-scoped
AOT core without treating either line's historical evidence as authority for
the new tree:

```text
b3cdc40885a81b9cb69c1f62edbb1017441baf56
  -> 96b1465e4da959f2954e1b333619d43ff169d3df  JIT + VL16 sessions
  -> 1b6d25636fd7b2509e19459e99a868ae8aa59f1e  reviewed AOT core
```

The AOT core was imported by an exact reviewed path set rather than by merging
the older integration branch. That preserves the current JIT, H, packed
literal, and Rebar source while adding the AOT crates, facade boundary, and
qualification tooling. Review of either input is not dynamic qualification of
this composed tree.

## Compiler boundary

LLVM is not the regex compiler. FRE's typed Kernel IR feeds custom direct
machine-code emitters:

- Search JIT and Search AOT use `fre-jit-aarch64` to produce the same typed
  `NativeImage` contract. The JIT gives an audited capability to
  `fre-jit-runtime` for strict-W^X publication; AOT revalidates and packages
  the already-emitted payload as deterministic Mach-O or ELF object bytes.
- Count-v2 AOT uses the separate focused direct-Count emitter in
  `fre-aot-aarch64`, then deterministic object and final-image glue layers.

`rustc` may use LLVM for FRE's Rust host/tool code, and a system linker places
the already-generated payload in a final executable. Neither tool selects,
optimizes, or generates the regex machine-code payload.

## Current JIT authority

The current exact-search facade keeps backend authority separate for Search
V8, tag 10, tag 19, and tag 21. All four production qualification atoms in
`crates/fre/src/qualified_exact_search_qualification.rs` are `Candidate`.
Candidate is not authorization: with no qualified atom the facade reports an
unqualified native status before host probing, emission, or publication.

When independently authorized, automatic selection prefers the tag-21 paired
ASIMD/fixed-VL16 SVE2 backend on an admitted Arm `0x41/0xd84`
ASIMD+SVE+SVE2+VL16 host, then considers tag 10, tag 19, and V8 under their own
authority. An atom for one backend cannot authorize another. VL16 thread
sessions remain same-thread-only and avoid a per-call vector-length syscall;
changing the thread's vector length invalidates the session contract.

Private scoped Candidate execution exists for tests and qualification source.
It does not manufacture a production `Qualified` atom or expose a
caller-controlled production setter. No historical JIT result is a deployment
or speed claim for this composed tree.

## Current AOT authority

The AOT compiler is source-first and inert. Its receipts bind the facade
source/plan, typed Kernel IR, native artifact, object, payload, metadata, and
resource identities, while `RuntimeAuthority::Absent` remains unconditional.
Compiling an object, linking a symbol, or enabling a feature cannot create a
qualified runtime row.

The static runtime verifies source-qualified rows before touching final-image
addresses and authenticates the retained payload, metadata, mapped
protections, target contract, and identities before returning a registry-owned
safe handle. The current Search production and qualification-private tables
are both empty. Count-v2 retains one exact selector-11 private Candidate row,
but its production table is empty while the promotion atom is all-zero.

The `fre` crate keeps `qualified-exact-search-jit` default-on. Its separate
`explicit-search-span-aot` feature is default-off and only binds an
already-adopted `VerifiedStaticSearchSpanV1` to the exact portable semantic
owner. It enables no link/adoption feature, creates no row, and changes no
default `PortableRegex` route.

## Evidence status

Historical macOS Count objects and measurements remain development evidence
for their exact source/artifact tuples. The composed Search path has not yet
completed fresh dynamic correctness, linked-image, tamper, lifecycle, or
AOT/JIT/portable timing validation. No Search row is promoted and no current
AOT performance or deployment claim is made.

An absolute temporary admission fence currently forbids new coordinator or
headroom-coordinator builds and timings until explicit live-cutover GO. This
docs checkpoint therefore uses source/static checks only. After GO, fresh
evidence must bind one exact composed commit, tree, source closure, toolchain,
binary, linked image, authority row, and retained raw result set before any
promotion or speed claim.

See [`AOT_TRACK_STATUS.md`](AOT_TRACK_STATUS.md) for the bounded Count/Search
scope and [`SEARCH_AOT_FACADE_BINDING.md`](SEARCH_AOT_FACADE_BINDING.md) for
the explicit public binding contract.
