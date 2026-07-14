# Native backend contract and security obligations

This file is normative for future x86-64 and AArch64 JIT/AOT implementations.
It separates semantic validation, target code generation and executable-memory
publication so that none of those layers can implicitly trust another.

## Entry ABI

Each compiled artifact has exactly one output contract and one IR cache
identity. The host shim validates the search window before entering native
code. The backend-neutral logical call is:

```text
kernel(haystack_base, haystack_len, window_start, window_end, result_slot)
    -> status
```

All lengths and offsets are target `usize`. `haystack_base` is readable for
exactly `haystack_len` bytes and may be null only when length is zero. The
window is half-open and must satisfy `start <= end <= haystack_len`. Absolute
anchors refer to the full haystack, never the window. `result_slot` has two
`usize` fields (`start`, `end`); a specialized `Exists` or `SelectedEnd` kernel
may omit unused stores but must use the same status encoding:

- `0`: no match; result fields are unspecified.
- `1`: match; fields required by the output contract are initialized.
- any other value: reserved for a host/backend fault, never a regex result.

The platform shim owns System V AMD64, Windows x64 or AAPCS64 register and
unwind details. Generated bodies use no Rust ABI. Callee-saved registers, stack
alignment, red zones and Windows shadow space follow the selected platform ABI.
The v1 leaf kernels neither unwind nor call arbitrary process addresses. Panic
or exception propagation across generated code is forbidden.

The cache key for machine code is not merely the semantic IR hash. It must also
include backend name/version, target triple, ABI version, code model, required
CPU-feature bitmap, tail-load policy and all code-generation options. A process
must feature-check before calling an artifact; AOT loaders must refuse a key
whose target or feature set does not match.

## Lowering and SIMD opportunities

| IR construct | Scalar/native lowering | SIMD candidate |
|---|---|---|
| `ScanLiteral` | length-specialized first/last-byte filter plus unrolled confirmation; anchored forms become one guarded compare | AVX2/AVX-512 or NEON multi-byte candidate masks; short literals as one or two vector equality reductions |
| `ScanClassStart` | scalar range/bitset membership loop | ASCII ranges via packed compares; arbitrary byte classes via nibble tables (`vpshufb`/NEON `tbl`) or backend-proved equivalent |
| `ExtendClassRun` | monotonic membership loop | vector membership mask followed by first non-member bit; scalar guarded tail |
| `ConfirmSuffix` | fixed-offset unrolled loads/comparisons | one or more exact vector compares and mask reductions; scalar or masked tail |
| anchors/window | eliminate scan or add one absolute equality check | no special vector operation |
| typed returns | direct status/register stores | not applicable |

Vector width is a backend choice and not semantic. Every vector load needs a
proof that its complete accessed range is within the search window/haystack, or
must use an architecture-correct masked load whose fault behavior is audited.
The baseline policy is **no read past `window_end` and no read before
`window_start`**, even if the allocation has padding. A scalar tail is always a
valid implementation. Guard-page tests must place both window boundaries next
to inaccessible pages and exercise every alignment and residual length.

Candidate masks must preserve the lowest absolute start. Greedy run extension
must find the first non-class byte. A backend may not reorder successful
candidates merely because a wider vector found them together. Native work must
remain within the validated linear certificate; helper calls with hidden
superlinear behavior are forbidden.

## Code emission and relocation

Emission first targets a non-executable, bounded byte buffer sized from a
checked backend estimate. Every append uses checked offsets and fails before
exceeding the admitted code/data/relocation limits. Branch relaxation and
literal-island placement are finite bounded passes with explicit work quotas.

Relocation records are typed. Validation before publication must prove:

1. relocation offset plus width is inside the code/data buffer;
2. records do not overlap unless a relocation kind explicitly permits it;
3. local branch targets begin at declared block labels;
4. PC-relative data targets lie inside the immutable artifact data section;
5. external targets are drawn from a per-backend allow-list of versioned leaf
   helpers with the same ABI and boundedness contract;
6. displacement arithmetic is checked and representable for the instruction;
7. x86-64 `rel32` range and AArch64 branch/literal ranges are verified after
   final layout; trampolines/islands themselves are bounded and validated;
8. persistent AOT artifacts contain no raw process addresses.

After relocation, a second decoder/disassembly audit must establish that all
direct control-flow targets are valid labels, indirect control flow is absent
in v1 bodies, forbidden instructions are absent, and every declared CPU
feature matches instructions actually emitted. Artifact bytes and relocation
metadata are hashed together after finalization.

## Executable-memory lifecycle

- Never map writable and executable at the same time. Allocate RW, emit and
  relocate, validate/hash, then transition to RX before publishing a pointer.
- Apple hardened runtimes require a narrowly isolated `MAP_JIT`/write-protect
  implementation; other platforms use their native dual-map or protection
  transition. Platform-specific unsafe code lives in a small backend crate,
  never this IR crate.
- Flush/invalidate instruction caches exactly as required, especially on
  AArch64, before publication and after the last write.
- Publication uses synchronization that makes finalized bytes visible before
  any thread can call them. Eviction waits for all callers (epoch, hazard or
  reference-count protocol) before unmapping. Reuse cannot create an ABA code
  pointer.
- A failed emission, relocation, validation or protection transition publishes
  nothing and drops non-executable storage.
- Fork, sandbox, code-signing, SELinux and seccomp behavior must be tested per
  supported embedding environment. JIT refusal is a typed build outcome; AOT
  or portable execution may be selected by the planner, never silently inside
  an already selected native kernel.

## Memory and speculation safety

All offset math is checked against `haystack_len` and the validated window
before address formation. Empty haystacks must not require dereferencing the
base pointer. Code/data pages are immutable after publication. Pattern bytes,
relocations and raw IR are untrusted cache inputs and are revalidated on load.

The ordinary contract prevents architectural out-of-bounds access. Embeddings
whose threat model includes Spectre-style disclosure across trust domains must
select and key a backend mitigation policy (for example, data-dependent index
masking or barriers after bounds checks). Such mitigation cannot be advertised
without target-specific tests and disassembly evidence.

## Qualification checklist

- Differential-test every emitted block and full program against the portable
  oracle, direct definitions and K0 across exhaustive small corpora, randomized
  large corpora, all alignments/windows/anchors and every supported CPU feature
  tier.
- Inject malformed IR, serialization, relocation and AOT object records.
- Run guard-page, sanitizer, Miri-for-host, fuzzing and concurrent cache
  publication/eviction tests.
- Record generated-code size, compile time, steady-state time, cold-cache time,
  branch/cache counters and fallback/refusal reasons.
- Inspect representative disassembly and automatically enforce the instruction
  and branch-target policy.
- Measure every applicable Rebar job and a frozen non-Rebar holdout. No backend
  becomes default from microbenchmarks alone.
