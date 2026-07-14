# Native publication security contract

This is the implementation contract for `fre-jit-runtime`. The first admitted
host is `aarch64-apple-darwin`; every other target returns a typed unsupported
outcome until it has its own tested publisher.

## State machine

```text
unmapped
  -> reserve PROT_NONE with one guard page on each side
  -> make only the checked, page-rounded payload RW
  -> copy code, zero alignment gap, copy rodata
  -> byte-compare copied payload and re-audit the immutable source image
  -> transition the complete payload RW -> RX (never RWX)
  -> perform required data/instruction cache synchronization
  -> publish immutable entry object with a release synchronization edge
  -> execute only through checked slice/window/result wrappers
  -> unmap only when the final owning reference and every call borrow are gone
```

Any syscall, audit, byte check, protection, or cache-maintenance failure goes
directly to an unpublished cleanup path. The cleanup path must tolerate every
intermediate state and may never call a generated entry.

The initial strict W^X implementation uses an RW mapping followed by
`mprotect(..., RX)`. Apple hardened-runtime `MAP_JIT` and
`pthread_jit_write_protect_np` are a separate target mode because their
entitlement and per-thread policy differ; failure of strict W^X is a typed JIT
denial, not permission to create an RWX mapping.

## Safe call boundary

The public API accepts a Rust haystack slice, checked half-open window, and a
typed output contract. Before the raw call it verifies:

- current architecture, OS, pointer width, endianness, ABI/backend versions,
  output kind, and required CPU features;
- `start <= end <= haystack.len()`;
- result storage is live and correctly aligned;
- mapping state is published RX and its retained identity matches the audited
  image.

The raw function-pointer conversion and call are isolated in one small unsafe
module. Status `0` and `1` are decoded according to the stamped output kind;
every other value is a backend fault. Generated code is leaf-only and cannot
unwind or call host addresses. A Rust panic, C++ exception, Unix signal, or
Mach exception may not cross this boundary.

## Required tests before planner use

- actual-hardware differentials for every emitted exact-literal and
  class/suffix shape, output kind, anchor combination, window, alignment, and
  scalar/NEON tier against both Kernel IR and the decoded simulator;
- empty slices and all vector-tail lengths;
- haystack allocations adjacent to inaccessible pages on both sides, plus
  windows ending at a guard boundary;
- code mapping guard pages, attempted post-publication writes, and mapping
  permission inspection where the OS exposes it;
- injected failure at reserve, RW transition, copy verification, RX transition,
  cache invalidation, and publication; no failure may leak a callable pointer;
- multi-threaded calls while ownership is cloned/dropped, plus proof that final
  unmap cannot race a call;
- malformed/tampered image refusal even though normal constructors return an
  already audited type;
- sanitizer/fuzz coverage where supported and explicit hardened-runtime,
  sandbox, fork, code-signing, and signal-ownership limitations.

Passing actual execution is correctness and memory-safety evidence, not a
performance win. Native compile, first call, warm call, code size, cache
pressure, Rebar, and frozen-holdout economics remain separate promotion gates.
