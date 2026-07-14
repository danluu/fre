# Native exact-literal aggregate design checkpoint

Status: implemented design checkpoint with differential/security tests. This
is a bounded research leaf, not facade routing or performance qualification;
timing remains prohibited until the sentinel quiet-window gate.

## Semantic contract

Kernel IR will own a separate aggregate contract instead of adding aggregate
variants to the existing one-match `OutputKind`:

- `AggregateOutput::{Count, SpanSum}` is distinct from
  `OutputKind::{Exists, SelectedEnd, Span}`;
- sealed `AggregateOperation` marker types select one exact result type and
  stable tag;
- `ExactAggregateProgram<A>` contains a validated unanchored exact-literal
  search program, an aggregate tag, and a domain-separated program identity;
- `ExactAggregateProgram<A>` is globally capped at `M <= 32`: construction,
  oracle preflight/execution, and native emission share one exact refusal at
  width 33. Wider literals require a distinct proved-linear program type;
- `build_exact_aggregate` is the only initial constructor. Classes, sets,
  captures, anchors, and general regex programs have no aggregate-emission API
  and are therefore typed refusals rather than semantic fallbacks.

The program identity hashes a new aggregate magic/version, aggregate-output
tag, and the complete serialized exact-search program. Thus Count and SpanSum
have different program and native-image identities even when their generated
instruction streams share most of their shape.

For byte haystack `H` of length `N` and literal `L` of length `M`, matches are
the Rust regex/Rebar Unicode-disabled, leftmost, successive non-overlapping
exact matches. For `M > 0`, after `[s,e)` the next search begins at `e`. For
`M == 0`, every byte boundary `0..=N` is selected: Count is `N + 1` and SpanSum
is zero. The empty case is emitted as a closed-form native result.

## Work and overflow theorem

The complete semantic/native leaf admits only `M <= 32`.

For `M > 0`, the candidate cursor is monotonic and a selected match advances
it by exactly `M`. The vector/scalar scheduler consumes disjoint envelopes:
for vector base `b`, a zero first/last-byte mask consumes `[b,b+15]` and moves
to `b+16`; a nonzero mask scans that envelope in increasing order. A miss moves
one start, while a match at `s` resumes at exactly `s+M`. If that remains in
the envelope scalar scanning continues; otherwise the next vector base is
strictly greater than `b+15`. Consequently no envelope is reloaded or skipped.
Long confirmation uses `v4/v5`, preserving the live `v0/v1/v3` filter state.

Independently of that tighter scheduler proof, let
`C=max(N-M+1,0)`. The conservative semantic/native work envelope is
`C*(M+1)+(floor(N/M)+1)`. Since `M<=32`, this is at most `34N+1` and is
therefore linear with a fixed implementation constant. Scratch is constant;
no admitted input can cause asymptotic `N*M` blowup. Width 33 receives the
same typed semantic refusal before emission.

Non-overlap makes selected nonempty spans disjoint. Consequently:

- nonempty Count `<= floor(N/M) <= N`;
- nonempty SpanSum `= Count*M <= N`;
- empty Count is `N+1`, and empty SpanSum is zero.

An admitted native call originates from a safe Rust slice on the 64-bit target,
so `N <= isize::MAX`; all four results fit `u64`, including empty `N+1`.
Construction and call preflight nevertheless use checked arithmetic and exact
caller-selected ceilings. Generated nonempty accumulation also checks for
wrap and returns a dedicated fault status, so an invariant violation cannot
publish a wrapped value. Unsupported pointer widths never publish this image.

The call preflight reports and checks haystack bytes, literal bytes, candidate
positions, maximum scheduler/confirmation work, match-event bound,
reducer-step bound, output bound, zero dynamic scratch, and exactly one native
invocation. Tests admit each exact bound, refuse one below every positive bound
before native entry, and admit a zero ceiling whenever the corresponding need
is zero. Bounds and overflow thresholds are also recomputed independently in
`u128` tests.

All vector loads retain the current proof: a block is entered only when 16
complete starts remain, so both the first-byte and `M-1` columns are within the
slice. Scalar confirmation is limited to starts at or before `N-M`. Empty and
too-short cases load no haystack bytes.

## ABI and image inventory

The existing search entry is unchanged:

```text
u64 search(ptr, len, window_start, window_end, *mut NativeResult)
```

Aggregate images use a separate typed image and entry signature:

```text
u64 aggregate(ptr, len, *mut NativeAggregateResult)
```

`NativeAggregateResult` is one aligned `u64` value. Aggregate status zero means
complete success; nonzero statuses are decoded as typed backend faults, with a
reserved arithmetic-overflow status. Search status and result decoding remain
unchanged.

Implemented image/runtime changes:

1. `NativeAggregateImage` is a distinct public wrapper with
   `AggregateOutput`, aggregate program identity, literal length, and the same
   immutable code/rodata/layout/resource receipts as `NativeImage`.
2. Aggregate AOT bytes use a distinct contract tag and include the aggregate
   output and aggregate program identity in the artifact digest.
3. The independent auditor selects its reserved result-pointer register,
   permitted result-store base, and return contract from the image type. It
   rejects every admitted decoded instruction form that writes the reserved
   register before checking stores. Search reserves `x4` and permits only its
   existing `x4` stores; aggregate reserves `x2` and permits only its `x2`
   value store. A valid store base therefore still denotes the original
   caller-provided pointer rather than an attacker-selected replacement. The
   aggregate-only contract also reconstructs identity from manifest/rodata,
   rejects x18 through x31 (including SP/LR/callee-saved state), authenticates
   x15/x16/x17 and x10 address-producer chains, admits only bounded literal and
   haystack load templates, checks every backward edge for cursor/confirmation
   progress, and requires all decoded instructions to be reachable. The sole
   store is immediately before status 0; status 1 cannot publish a partial
   result.
4. Publication retains the same three independent audits, byte verification,
   guard pages, RW-to-RX transition, and instruction-cache invalidation.
   `publish` remains source compatible; `publish_aggregate` returns a typed
   aggregate kernel and invokes the three-argument entry exactly once.

## Runtime and cache type inventory

The runtime has a sealed `RuntimeAggregateOperation` for Count and SpanSum and
a distinct `PublishedAggregateKernel<A>`/`publish_aggregate` path. Search and
aggregate retain separate public image types, publication functions, call
methods, and entry signatures. The aggregate method performs the complete
ceiling preflight and invokes native code exactly once. On status 0 it validates
Count against `N+1` (and the stronger nonempty `floor(N/M)` bound), and validates
SpanSum as zero for empty or otherwise `<=N` and divisible by `M`. On fault it
ignores the poisoned result slot.

The cache implementation can then generalize from `RuntimeOperation` to
`RuntimeContract` without changing existing `KernelCache<Span>` call sites.
`KernelCache<Count>` accepts only `NativeAggregateImage` for Count, and the
same applies to SpanSum. Admission checks all of:

- the compile-time contract marker;
- image contract and aggregate-output tag;
- domain-separated artifact/runtime identity;
- independently audited mapping contract;
- publication accounting and cache limits.

Search, Count, and SpanSum are non-interchangeable at the type, image,
publication, and identity layers. Cache generalization remains deliberately
deferred until the sentinel passes.

Aggregate program identity hashing is construction work over a fixed
width-capped serialization envelope. Native artifact hashing is charged in
emission work by the complete aggregate AOT byte count. Neither is hidden
haystack-dependent call work.

## Validation and measurement gate

Before timing, differential tests will cover arbitrary bytes, all relevant
literal lengths through the admitted cap, alignments, vector tails, dense and
overlapping candidates, inaccessible left/right pages, empty literals and
empty haystacks, typed limit boundaries, tampered operation identities, and
all injected publication failures.

Measurements will use fresh sequential processes and retain raw samples. They
will compare one native aggregate call with the old per-match JIT loop, pinned
Rust regex, and `fre-kernels` on Sherlock and every one of the 24 authenticated
currently exact-routed Rebar jobs whose literal width is admitted. No routing
or promotion claim is permitted unless the complete audited boundary wins.
