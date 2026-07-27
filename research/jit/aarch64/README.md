# Bounded AArch64 native-image backend

`fre-jit-aarch64` is the first executable-ISA lowering layer for validated FRE
Kernel IR. It emits ordinary pattern-specialized AAPCS64 machine code, not
regex bytecode and not a dispatch loop. The crate contains no unsafe code and
does **not** make its output executable. `fre-jit-runtime` is the separate,
narrowly unsafe strict-W^X publisher, and `fre-jit-cache` owns bounded
publication caching. The only high-level route is the explicit
`fre::QualifiedExactSearch` facade; no default planner selects native
execution. Search V7 is qualified only for that facade's 16-byte
large-window/reuse envelope. Its promotion is a direct child of exact measured
commit `88e9c22c4ac382531bc1026ca0e25587905f5206` and binds external bundle
SHA-256
`de084ff0564acdb89889f28b9dcfddce9b6f0955a1b2aead30d75770039e0453`.

## Admitted kernels

The search-v7 emitter recognizes only the two canonical shapes that
`fre-kernel-ir` can currently certify:

1. exact byte literals with every combination of absolute start/end anchors;
2. greedy `[class]+suffix` when the non-empty suffix's first byte is proved not
   to belong to the class.

Unanchored non-empty exact search chooses a deterministic rare byte pair from
the literal. When at least 16 candidate starts remain, NEON compares the
primary byte column and consults the secondary column only for primary-hit
blocks. V7 ranks two additional distinct literal columns, applies them in
stages only while candidates survive, and then packs the 16 exact candidate
bytes into a sparse scalar mask. Lowest-set-lane recovery and bit clearing
preserve exact left-to-right order without rescanning adjacent pairs.
The final incomplete block is scalar. A 16-byte candidate is confirmed with guarded NEON
equality/reduction; other widths use the length-specialized confirmation loop.
Arbitrary byte classes use four little-endian `u64` lanes and a variable shift.
Class-run extension is monotonic. The disjoint delimiter proof means it never
backtracks inside a run.

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

The body uses only caller-saved `x0..x17` and `v0..v7`, makes no calls, uses no
stack, cannot unwind, and contains no indirect branch. The independent search
audit rejects any vector operand outside `v0..v7`, including the AAPCS64
callee-saved `v8..v15` range. Existence kernels omit
result stores, selected-end kernels store offset 8, and span kernels store
offsets 0 and 8. A defensive prologue rejects `start > end` or
`end > haystack_len` without touching the haystack, although a publisher must
still validate all pointers and the result slot before entry.

`NativeImage` contains separate code and rodata byte strings, their required
relative placement/alignment, declared code labels and data symbols, the
source Kernel IR cache identity, a sealed search manifest, target/feature
contract, exact resource statistics, and sorted typed relocations. The search
manifest binds the backend version, admitted shape, output, anchors, literal
facts, candidate-policy revision, block width, selected pair and verification
offsets, and source identity into the artifact identity. Search v6 uses AOT
wire tag 6 and exact sparse per-lane recovery. Historical search v5 retains
wire tag 5 and tertiary-filtered pair-group recovery, search v4 retains sealed
wire tag 4, v3 retains sealed wire tag 3, and search v1 and v2 containers
retain manifest-free wire tag 1. Golden artifact identities prove that adding
v6 leaves canonical v1-v5 AOT bytes unchanged. Every version is dispatched to
a complete versioned template; aggregate wire v1 is unchanged.
Pre-c4d aggregate images carrying historical backend tag 2 authenticate
against the same unchanged aggregate-v1 template. Search audit dispatch is
version- and authenticated-envelope-driven rather than inferred from opcode
markers or mutable code prefixes. Branch and ADR relocations are fully resolved using checked
signed-range arithmetic; their symbolic targets remain in the manifest. There
are no process addresses or external helper targets.
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

- sealed v3, v4, v5, and v6 manifests agree with the target backend, output, anchors,
  symbols, immutable literal bytes, independently recomputed candidate policy,
  and rebuilt Kernel IR identity before template dispatch;
- search v1, v2, v3, v4, v5, and v6 each match a complete, independent per-shape template,
  including anchored and unanchored exact and class-suffix forms;
- search and aggregate manifests are mutually exclusive, and aggregate shape,
  identity, and operation accounting flow through one authenticated envelope;
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

## Correctness and qualification evidence

The safe test-only ISA model executes the independently decoded emitted bytes,
including flags, branches, memory bounds and NEON reductions. It is not a
parallel regex implementation. Differentials against the Kernel IR oracle
cover exact, anchored, class/suffix, all-output, window-boundary and guarded
native execution. Exact retained counts are generated by the current test run
and recorded in [`../STATUS.json`](../STATUS.json); this document intentionally
does not carry stale snapshot counts.

Guard-page cases include both rare-pair address orders, first and last vector
lanes, present and absent results, nonzero windows, fixed-16 false-pair scalar
confirmation at the right boundary, and resumption to a distant match. Native
ABI tests preserve `v8..v15`; audit mutation tests reseal hostile images before
requiring rejection.

Exact-boundary and one-below tests cover code bytes, data bytes, relocations,
labels, emission work, logical scratch and AOT bytes. Unit tests separately
exercise the last encodable and first refused PC-relative displacements.

[`code-shapes.csv`](code-shapes.csv) is reproduced with:

```sh
cargo run -p fre-jit-aarch64 --example code_shapes --quiet
```

The generated table is the authority for current image sizes. Code size is
constant within each emitted template tier; longer patterns grow rodata and
metered confirmation work.

## Layer boundary and remaining blockers

`fre-jit-runtime` re-audits before publication, checks the target and
backend-version contract, allocates/copies under RW permissions, transitions
to RX/RO without a simultaneous writable/executable mapping, performs required
instruction-cache maintenance, validates calls, and owns mappings through
typed reference-counted kernels. `fre-jit-cache` exposes only cache-accounted
leases from its public builder path.

The decoded-ISA differential still does not substitute for actual-hardware
guard pages, ABI canaries, cache coherency or performance evidence. The
qualified explicit leaf passed the full correctness/lint/docs gates, honest
cold and amortized workload accounting, source-bound alternating A/B matrices
including all losses and adversarial holdouts, and an independent review.
Those results do not qualify any other width, operation, architecture, AOT
loader, or default planner route; the rest of the native facade remains
experimental.
