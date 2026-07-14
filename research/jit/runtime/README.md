# AArch64 macOS native-publication evidence

Status on 2026-07-14: the narrow strict-W^X publisher executes both currently
emitted Kernel IR shapes on an Apple M5 Max. This is a correctness and
memory-safety gate, not evidence of a performance win or planner readiness.

## Admitted path

- Host: `aarch64-apple-darwin`, 64-bit little-endian AAPCS64 v1.
- Machine used for this run: Apple M5 Max, MacBook Pro `Mac17,7`, 48 GB.
- OS/toolchain: macOS 26.5.2 (25F84), rustc 1.93.0.
- VM page size: 16,384 bytes; baseline Advanced SIMD is available.
- Policy: reserve `PROT_NONE`, with one guard page on each side; change only
  the middle page-rounded payload to `PROT_READ|PROT_WRITE`; zero it, copy code
  and rodata at their audited relative offsets, byte-compare code/data and all
  zero gaps, and audit the source image again; change the complete payload to
  `PROT_READ|PROT_EXEC`; call `sys_icache_invalidate` on the code bytes; only
  then construct the private entry pointer and publish the safe typed object.
- No operation asks for RWX. `MAP_JIT` and
  `pthread_jit_write_protect_np` are not used. An `EPERM` or `EACCES` is a
  typed `JitDenied`, not a reason to weaken W^X.
- Publication charges exact code, data, used payload, page-rounded payload,
  two guard pages, total mapped bytes, and page count before any reservation.

The test-only `mach_vm_region` query observed `PROT_NONE` on both guards and
`PROT_READ|PROT_EXEC` (without `PROT_WRITE`) on the published payload.
An isolated fork child then attempted a volatile write to the published code;
the OS terminated it with `SIGBUS` or `SIGSEGV`, while the parent and mapping
remained valid.

## Correctness evidence

Fresh actual-hardware differentials against the safe Kernel IR oracle:

| Shape | Hardware comparisons | Coverage |
|---|---:|---|
| exact literal | 354,096 | Exists, SelectedEnd, Span; all four anchor combinations; every checked subwindow; empty, 1/2, 16/17, and 64-byte literals |
| proved-disjoint class+suffix | 308,988 | Exists, SelectedEnd, Span; all four anchor combinations; every checked subwindow; scalar and 17-byte suffixes |
| total | 663,084 | no mismatch or native fault |

An additional 1,024 calls vary the haystack allocation offset and every tail
length from 0 through 31 for a 17-byte vector literal. Direct native calls also
passed with haystacks placed at both edges of inaccessible pages for an empty
literal, a 17-byte literal, and a vector-suffix class kernel. Eight threads
each made 2,000 calls while clones and the original owner were dropped.

The AArch64 emitter already compares its private decoded-ISA simulator against
Kernel IR (107,976 exact-literal and 347,940 class+suffix comparisons). That
simulator is test-private and therefore is not imported across the production
crate boundary. The runtime instead reuses the public authenticity decoder and
auditor before publication, and adds the independent hardware-to-Kernel-IR
comparisons above. These are two linked evidence sets, not a claim that all
three ran over one identical corpus.

Rollback injection covers reserve, RW transition, copy, byte verification,
source re-audit, RX transition, cache invalidation, and final publication. A
separate injected copy corruption reaches the byte verifier. Every case returns
without a published pointer and the test mapping counter returns to zero.

Safe construction of `NativeImage` keeps its byte and manifest fields private;
the emitter's own tests mutate crate-private images to prove the auditor rejects
unknown instructions and altered relocations. At this boundary, output-type
mismatch is rejected before mapping and copied-byte tampering is rejected before
RX. A future untrusted AOT loader will need its own malformed-container suite.

## Diagnostic lifecycle timing

`hardware-diagnostics.csv` is one release-mode run of
`cargo run -p fre-jit-runtime --release --example hardware_diagnostics`. The
64 KiB haystacks and 2,000 repeated calls are deliberately recorded only to
make lifecycle costs visible. This is neither a controlled benchmark nor a
speed comparison.

## Verification

The following gates pass:

```text
cargo test -p fre-jit-runtime --all-targets
cargo clippy -p fre-jit-runtime --all-targets --all-features -- -D warnings
RUSTDOCFLAGS='-D warnings' cargo doc -p fre-jit-runtime --no-deps
```

Miri was checked but is unavailable for the installed
`1.93.0-aarch64-apple-darwin` toolchain. The safe planning/output-decoding code
contains no unsafe blocks; all executable-memory, cache, VM introspection,
guarded-test allocation, and raw-call operations remain in
`platform/macos_aarch64.rs`, with `unsafe_op_in_unsafe_fn` denied and each
unsafe block documented.

## Explicit limitations

- Every non-AArch64-macOS target returns a typed unsupported-host result.
- Hardened-runtime/code-signing environments that require `MAP_JIT` are not
  admitted. Entitlements and per-thread write-protection need a separate
  publisher and tests.
- Sandbox profiles may deny anonymous executable mappings; this is surfaced,
  not bypassed.
- There is no global executable cache, eviction policy, fork protocol, AOT
  loader, or post-fork validity guarantee yet.
- Generated signals and Mach exceptions are not caught. Native code must be
  leaf-only and may not unwind; a generated fault remains process-fatal.
- `Drop` calls `munmap` after the final `Arc` and every call borrow end. Because
  Rust destructors cannot return errors, a rare `munmap` failure can retain
  unreachable RX pages but cannot publish or retain an API-callable pointer.
- Actual execution passing does not promote either shape into the regex
  planner. Rebar, holdout, compilation-economics, code-size/cache-pressure, and
  end-to-end semantic gates remain separate.
