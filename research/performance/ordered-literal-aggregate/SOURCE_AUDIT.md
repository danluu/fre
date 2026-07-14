# Pinned packed-search source audit

Audited dependency: crates.io `aho-corasick` 1.1.4, package checksum
`ddd31a130427c27518df266943a5308ed92d4b226cc639f5a8f1002816174301`.
The local audited root was:

```text
/Users/danluu/.cargo/registry/src/index.crates.io-1949cf8c6b5b557f/aho-corasick-1.1.4/src/packed
```

The path is machine-local; the package checksum and file hashes are the durable
identity:

| File | SHA-256 |
|---|---|
| `api.rs` | `2197077ff7d7c731ae03a72bed0ae52d89fee56c5564be076313c9a573ce5013` |
| `rabinkarp.rs` | `403146eb1d838a84601d171393542340513cd1ee7ff750f2372161dd47746586` |
| `pattern.rs` | `0e4bca57d4b941495d31fc8246ad32904eed0cd89e3cda732ad35f4deeba3bef` |
| `teddy/builder.rs` | `08ec116a4a842a2bb1221d296a2515ef3672c54906bed588fb733364c07855d3` |
| `teddy/generic.rs` | `ea252ab05b32cea7dd9d71e332071d243db7dd0362e049252a27e5881ba2bf39` |
| `vector.rs` | `70c325cfa6f7c5c4c9a6af7b133b75a29e65990a7fe0b9a4c4ce3c3d5a0fe587` |

Line numbers below refer exactly to those hashes.

## Dispatch, semantics, and progress

- `api.rs:253-281` clones the patterns, builds Rabin-Karp, requires a Teddy
  searcher in the public path, and records its minimum length.
- `api.rs:292-320` preserves insertion order and makes an empty pattern render
  the builder inert. The local plan rejects empty alternatives before this.
- `api.rs:529-545` dispatches a suffix to Teddy unless it is shorter than the
  Teddy minimum, in which case `api.rs:640-647` uses Rabin-Karp.
- `api.rs:580-586` constructs `FindIter` from references and a `Span`.
  `api.rs:666-686` shows that `next` calls `find_in` and restarts at `m.end()`.
  Because the local theorem admits only nonempty patterns, every successful
  restart strictly advances.
- `pattern.rs:157-176` defines match-order iteration. `teddy/generic.rs:786-805`
  groups ambiguous prefixes in one bucket, and `teddy/generic.rs:849-865`
  verifies bucket patterns in that order. These facts preserve leftmost-first
  priority, including duplicates.

## The 36-position charge

`teddy/builder.rs:122-125` and `241-265` cap the Teddy mask length at four.
The generic slim loops are `teddy/generic.rs:114-134`, `184-206`, `241-265`,
and `308-338`; the fat loops are `447-467`, `517-539`, `574-598`, and
`641-671`. They advance one vector (or fat half-vector) and may reset to
`end - vector_width` for one terminal visit.

The largest vector is 32 bytes on x86 AVX2 (`vector.rs:421-433`). x86 SSSE3 is
16 bytes (`vector.rs:328-340`) and AArch64 NEON is 16 bytes
(`vector.rs:609-621`). Two-, three-, and four-byte masks verify from
`cur - 1`, `cur - 2`, or `cur - 3` respectively
(`teddy/generic.rs:211-234`, `270-301`, `343-378`; fat equivalents begin at
`544`, `603`, and `676`). Thus 32 vector bytes plus three history bytes plus one
inclusive-boundary charge is 36. A terminal revisit is possible in every
successful call and in the final no-match call, so the implementation charges
`36 * (floor(N/m) + 1)`, not merely one charge per match.

## Candidate verification and fixed work

`teddy/generic.rs:820-865` consumes candidate bits and visits patterns in the
chosen bucket. Each pattern occurs in one bucket (`786-805`). Prefix checks
first reject insufficient haystack and compare exactly the pattern length
(`pattern.rs:265-279`); the comparison is a bounded short-byte loop
(`pattern.rs:368-415`). Therefore all verifications charged to one candidate
position visit at most `P` patterns and compare at most `T` bytes.

The short-suffix engine is also bounded: `rabinkarp.rs:86-115` advances `at` by
one with a constant-time rolling hash and visits the selected bucket;
`rabinkarp.rs:135-146` uses the same bounded prefix comparison. Its initial hash
loop is bounded by the minimum literal length, which is at most `W` and is
covered by the per-call fixed charge.

The local abstract-work envelope is consequently
`Q*(T + P + 64) + 64*C`. The 64-unit terms deliberately dominate the fixed
source-level mask loads, boolean/vector operations, lane/bucket control, hash
updates, iterator dispatch, and final test. This is a source-work bound, not a
claim about retired instructions or cycles. With the immutable absolute caps
`P<=16`, `W<=32`, and `T<=512`, it proves no input- or regex-dependent
superlinear operation path.

## Operation allocation audit

After construction, the local count/span functions create only scalar counters
and the three-field borrowed `FindIter`. The reachable search code cited above
uses stack scalars, borrowed slices/pointers, vector registers, and retained
buckets. It contains no `Vec`, `Box`, `Arc`, map insertion, collection, result
buffer, or allocator call. The operation therefore has zero external scratch
and performs no dynamic allocation. Persistent plan memory and caller-owned
haystack storage are excluded from scratch and are reported separately. The
fixed-size thread-stack frame and allocator metadata are excluded from peak;
neither varies with the haystack or admitted regex shape.

## Construction gap: research-only

This dependency is not suitable for production resource certification as used:

- `api.rs:257-281` clones `Patterns` and creates `Arc` allocations.
- `rabinkarp.rs:70-80` creates nested bucket vectors and pushes entries.
- `teddy/generic.rs:762-770` allocates bucket vectors and a `BTreeMap`;
  `771-805` allocates low-nybble keys and pushes bucket entries.
- target wrappers allocate retained `Arc` implementations, for example
  `teddy/builder.rs:493-500`, `557-568`, `629-636`, and `759-766`.

Those are infallible dependency-internal allocations. The local preflight's
build-work constants (4096 per pattern byte/entry plus 1 MiB fixed) and peak
constants (4096 bytes per pattern byte, 64 KiB per entry, plus 4 MiB fixed)
are intentionally oversized finite envelopes for the absolute admitted set.
At the maximum admitted shape, build work is 3,211,264 abstract units and the
peak envelope is about 7.00 MiB plus the inline plan, below the 4 MiB/16 MiB
defaults respectively. But these are conservative admission envelopes, not a
measured allocator peak or a way to make internal allocation failure typed.
Allocator metadata is excluded. `Searcher::memory_usage` is itself documented
as approximate at `api.rs:631-638`.

Production promotion therefore requires replacing or wrapping construction with
a locally controlled, fallibly allocated packed representation and validating
actual peak capacity. The general reverse plan already follows that resource
model.

## Cache identity

The packed identity encodes ordered, length-prefixed bytes, operation, exact
semantics, absolute proof caps, package version/checksum, target architecture,
and the runtime Teddy minimum length. It is explicitly process-local: the
builder's selected Teddy variant and CPU features are not exposed as a stable
serializable representation. Limits are not semantics and must be revalidated
on reuse.
