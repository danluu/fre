# Bounded AArch64 native-image backend

`fre-jit-aarch64` is the first executable-ISA lowering layer for validated FRE
Kernel IR. It emits ordinary pattern-specialized AAPCS64 machine code, not
regex bytecode and not a dispatch loop. The crate contains no unsafe code and
does **not** make its output executable. Its current status is a qualified
native-image prototype, not a production JIT publisher or a default planner
choice.

## Admitted kernels

The v1 emitter recognizes only the two canonical shapes that
`fre-kernel-ir` can currently certify:

1. exact byte literals with every combination of absolute start/end anchors;
2. greedy `[class]+suffix` when the non-empty suffix's first byte is proved not
   to belong to the class.

The exact-literal search uses a NEON 16-byte first-byte filter for unanchored
literals of at least 16 bytes. Candidate confirmation uses guarded 16-byte
NEON equality/reduction and a scalar tail. Short literals use a scalar,
length-specialized loop. Arbitrary byte classes use four little-endian `u64`
lanes and a variable shift. Class-run extension is monotonic. The disjoint
delimiter proof means it never backtracks inside a run.

Every vector load is reached only after proving that a complete 16-byte region
lies inside the checked window or the immutable pattern object. Scalar tails
perform no read past either end. Exact literal worst-case work is
`O((window + 1) * (literal + 1))`; class/suffix work is
`O((window + 1) * (suffix + 1))`. Both are bounded by the validated Kernel IR
work factor and neither has an exponential or input-dependent state explosion.

## ABI and image contract

The logical call is a leaf AAPCS64 function:

```text
x0 = haystack base
x1 = haystack length
x2 = window start
x3 = window end
x4 = result slot { usize start, usize end }
w0 = 0 (none) or 1 (found)
```

The body uses only caller-saved `x0..x17` and `v0..v1`, makes no calls, uses no
stack, cannot unwind, and contains no indirect branch. Existence kernels omit
result stores, selected-end kernels store offset 8, and span kernels store
offsets 0 and 8. A defensive prologue rejects `start > end` or
`end > haystack_len` without touching the haystack, although a publisher must
still validate all pointers and the result slot before entry.

`NativeImage` contains separate code and rodata byte strings, their required
relative placement/alignment, declared code labels and data symbols, the
source Kernel IR cache identity, target/feature contract, exact resource
statistics, and sorted typed relocations. Branch and ADR relocations are fully
resolved using checked signed-range arithmetic; their symbolic targets remain
in the manifest. There are no process addresses or external helper targets.
`AotArtifact` serializes the complete structure deterministically in a
little-endian, address-free container. It is an FRE interchange container,
not ELF or Mach-O yet. Its `ArtifactIdentity` is SHA-256 over the complete AOT
bytes, so code, data, target metadata and the relocation manifest are all
covered by one content identity.

Emission streams that same canonical encoding directly through SHA-256
without allocating an AOT buffer, charges the encoded byte count to emission
work and the hasher state to peak scratch, and stores the digest in immutable
`NativeImage`. The stored digest field itself is deliberately excluded from
the canonical encoding, avoiding a circular hash. The encoded statistics are
the final post-charge emission-work and scratch values. Tests prove the stored
digest equals a separately materialized `AotArtifact::identity()` and changes
with image content and output contract. Reading it later is a constant-sized,
allocation-free copy with no rehash.

The only public construction path for `NativeImage` is `emit`, which computes
the digest and then audits the finalized image before returning it; cloning
preserves the immutable image and digest. There is no AOT loader today. Any
future loader must parse into a private candidate, recompute and compare the
canonical digest, fully audit the image and target, and only then construct a
public `NativeImage`.

## Independent authenticity pass

Emission is followed by a small decoder that shares no encoder helpers. The
audit rejects every instruction outside the admitted scalar/ASIMD subset and
checks:

- every direct branch target is aligned, in code, and a declared label;
- every ADR names a declared immutable data object;
- relocation records are complete, sorted, non-overlapping and byte-exact;
- stores can address only the two result-slot fields through `x4`;
- the feature bitmap exactly reflects decoded vector instructions;
- section, symbol and aggregate image bounds agree with the manifest.

Tests mutate instructions and relocation words to ensure the audit fails, and
feed malformed control flow to the upstream total IR validator. The public
emitter accepts only `ValidatedProgram<O>`, so malformed raw IR is
unrepresentable at its entry point.

## Qualification evidence

The safe test-only ISA model executes the independently decoded emitted bytes,
including flags, branches, memory bounds and NEON reductions. It is not a
parallel regex implementation. Current differentials against the Kernel IR
oracle cover:

- 107,976 exact-literal combinations across empty/short/16/17-byte literals,
  all four anchor combinations, exhaustive small haystacks, directed SIMD
  cases and every valid search window;
- 347,940 proved-disjoint class/suffix combinations across multiple classes,
  short and 17-byte suffixes, all anchors, exhaustive ternary haystacks,
  directed SIMD cases and every valid window;
- all three output contracts through the same native result ABI.

Exact-boundary and one-below tests cover code bytes, data bytes, relocations,
labels, emission work, logical scratch and AOT bytes. Unit tests separately
exercise the last encodable and first refused PC-relative displacements.

[`code-shapes.csv`](code-shapes.csv) is reproduced with:

```sh
cargo run -p fre-jit-aarch64 --example code_shapes --quiet
```

The current unanchored images are 60 bytes for an empty literal, 172 bytes for
a 1--15-byte literal, 280 bytes for a SIMD literal, 248 bytes for a scalar
class/suffix kernel, and 296 bytes for a class kernel with SIMD suffix
confirmation. Code size is constant with pattern length in each tier; longer
patterns grow only rodata and emission work.

## Deliberately remaining outside this crate

A production publisher must remain a separate, narrowly unsafe platform layer
and must complete all of the following before any native backend can be called
or benchmarked as a JIT:

- re-audit the received image and its target/cache key;
- allocate RW memory, copy code/data with the exact declared layout, then make
  it RX/RO without any simultaneous writable/executable mapping;
- implement Apple `MAP_JIT`/write-protect and Linux/BSD protection policies;
- perform the architecture/OS-required data and instruction-cache maintenance
  and publish with a synchronization edge;
- validate non-null/readable/writable call arguments in a safe host shim;
- add guard pages on both haystack/window boundaries and test every alignment
  and tail length on actual hardware;
- contain illegal-instruction and memory faults without unwinding through
  generated code, and define signal/exception ownership for embeddings;
- feature-check ASIMD, target ABI, endianness, pointer width, backend version,
  tail policy and mitigation policy as part of every cache/AOT load;
- use epochs/hazards or equivalent so concurrent calls cannot race eviction,
  unmapping or ABA address reuse;
- qualify actual execution under sanitizers where applicable, hardened runtime,
  sandbox, fork and code-signing configurations;
- compare native execution, compile latency, cold-cache behavior, counters,
  every relevant Rebar job and frozen non-Rebar holdouts before planner
  admission.

The decoded-ISA differential proves the instruction semantics intended by this
emitter. It does not substitute for actual-hardware guard-page, cache-coherency,
fault-containment or performance qualification.
