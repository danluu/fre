# Exact-width x86 AVX-512 classifier qualification

`fre-simd-kernels` contains a general 32-byte implementation of its compiled
ASCII byte-set classifier using AVX-512F, AVX-512BW, and AVX-512VL. The safe
entry point still accepts `&[u8; 32]`; the private leaf uses YMM registers and
opmask results, so it neither widens the load nor assumes 64 readable bytes.
Its stable selection receipt is
`ascii-byte-set.mask32.avx512f-bw-vl.v1` and names all three required features.
The leaf deliberately has no Rust `target_feature` attribute: stable Rust
implicitly adds AVX2, FMA, and F16C to an AVX-512F function's call contract.
One reviewed inline-assembly body instead fixes the complete instruction set,
while the retained runtime entry proves exactly F/BW/VL before any call.

The AVX-512 variant has lower generic preference than AVX2. Automatic dispatch
therefore keeps the already-qualified AVX2 choice on a host that supports both.
AVX-512 is selectable for direct qualification by removing AVX2 with
`DispatchPolicy::AllowOnly`; a proper subset of F/BW/VL cannot authorize the
leaf and safely falls back to AVX2, split-16, or scalar according to the
remaining real host features. A future microarchitecture-specific preference
requires fresh native evidence and a separate tuning predicate.

## Native gate

The provider-neutral Linux x86 qualifier accepts a clean commit/tree and runs
the full process at one declared CPU affinity:

```text
scripts/qualify-simd-x86.sh \
  --commit COMMIT \
  --tree TREE \
  --receipts /path/outside/source/receipts \
  --bench-cpu CPU \
  --bench-iters 5000000 \
  --samples 16
```

The selected CPU must expose OS-usable AVX2 plus AVX-512F/BW/VL. The
`FRE_SIMD_REQUIRE_AVX512=1` test sentinel fails when any AVX-512 requirement is
absent; it never converts a required native gate into a skip. Qualification
has no benchmark-disable option.

The qualifier produces separate debug, release, codegen, unsafe-boundary,
feature, and benchmark logs. Release codegen must show AVX-512 byte opmask
instructions and opmask registers, contain no ZMM register in the exact-width
leaf, and retain `vzeroupper`. The benchmark runs at least 15 alternating
AVX2-first/AVX-512-first paired samples with a positive configurable iteration
count. Its validator recomputes both medians and their ratio from the preserved
raw arrays before qualification can pass.

Receipts record the exact commit and tree, Rust and Cargo versions, CPU
description and topology, microcode, frequency governor, and the affinity of
the pinned process. A manifest hashes every receipt. The complete directory is
renamed atomically into the requested path only after every gate passes and the
source identity is rechecked. The script assumes no AWS, SSH, container, or
cloud-provider facility.

Implementation and cross-compilation alone establish no speed claim. Promotion
or a tuned preference requires a complete native receipt from the declared
hardware.
