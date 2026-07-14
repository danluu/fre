# System V AMD64 v1 backend contract

## Entry ABI

The generated leaf has the C-compatible conceptual signature:

```c
uint32_t entry(const uint8_t *haystack, size_t haystack_len,
               size_t window_start, size_t window_end,
               struct { size_t start; size_t end; } *out);
```

System V AMD64 places these arguments in RDI, RSI, RDX, RCX and R8. EAX is one
of `0` (no match), `1` (match) or `2` (invalid window). The output is the
canonical span for all Kernel IR output kinds; a safe publisher projects that
span to Exists, SelectedEnd or Span. No-match and invalid-window returns zero
both output words.

Caller obligations:

- `out` is non-null and writable for 16 bytes.
- `haystack` addresses at least `haystack_len` readable bytes. It need not be
  dereferenceable when no generated path reads a byte.
- the publisher checks the target and CPU-feature stamps before calling.

The leaf makes no calls, does not adjust RSP, uses no red zone or stack scratch,
and writes no callee-saved register. It reads only the checked search window and
immutable in-image constants, and writes only `out`.

Windows x64 has a distinct public target stamp and is rejected. It is never
silently treated as System V.

## Search shapes and bounds

Exact literals use immediate overlapping 1/2/4/8-byte comparisons up to 16
bytes. Longer literals use a RIP-relative constant and a scalar, SSE2 or AVX2
confirmation loop. The last legal candidate remains in R10 across rejection.
The upper bound is `O((window_width + 1) * (literal_len + 1))`, matching the
Kernel IR work-factor model; there is no backtracking or data-dependent state
growth.

Disjoint class suffixes use immediate equality tests for classes of population
at most four and a 256-byte membership table otherwise. The cursor advances to
the end of every non-empty maximal class run. The proof that the suffix's first
byte is outside the class guarantees progress. Suffix confirmation is bounded
as above, so the whole search is `O(window_width * (suffix_len + 1))` with zero
runtime allocation and zero runtime scratch.

SSE2/AVX2 currently accelerate confirmation, not candidate discovery. The
feature stamp records both the requested maximum tier and the highest tier
actually present in decoded instructions. AVX2 publication must check CPUID,
OSXSAVE and XCR0 state; every AVX2 return executes `vzeroupper`.

## Immutable image

One image is laid out as code, deterministic padding, then immutable data.
RIP-relative i32 references are resolved for that exact contiguous layout. An
auditable manifest retains source displacement offsets and data targets. A
publisher must copy the complete image without changing offsets.

Emission has explicit limits for code, data, total image, relocations, direct
branches, branch and relocation displacement, work, scratch, runtime work
factor and runtime scratch. Labels and fixups live in fixed-size safe Rust
arrays. All arithmetic and heap reservation are checked.

The independent decoder accepts only the emitted instruction subset. It rejects
unknown bytes, calls, indirect jumps, stack modification, unchecked branch
targets, non-instruction branch targets, inconsistent relocations, feature-tier
mismatches and missing AVX cleanup. RET is the only permitted indirect transfer.

The AOT container records the complete target/ABI/tier stamp, Kernel IR semantic
identity, output kind, semantic shape, section dimensions and relocation
manifest in little-endian form. Loading it still requires re-auditing the image.

## Deliberately separate unsafe boundary

This crate contains `#![forbid(unsafe_code)]` and never creates executable
memory. A production publisher still needs:

- platform feature detection and cache-key integration;
- one authenticated copy followed by a W^X permission transition;
- platform instruction-cache synchronization;
- guard pages and exact mapping/layout checks;
- a narrowly reviewed unsafe function-pointer call boundary;
- lifetime/reclamation rules preventing calls into unmapped code;
- Windows ABI lowering and unwind/CFG metadata where required;
- real x86-64 scalar/SSE2/AVX2 execution qualification in CI.

The external qualification harnesses in this research directory do not satisfy
those production obligations.
