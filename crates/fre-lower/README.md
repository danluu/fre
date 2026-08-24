# `fre-lower`

`fre-lower` is the checked boundary between `fre-syntax` HIR and the portable
capture-free K0 engine in `fre-automata`. It is deliberately independently
testable: syntax parsing produces immutable HIR, this crate produces a
`RawPlan`, and `fre-automata` validates that plan again before search.

## Current semantic certificate

The first certificate covers:

- empty expressions and fixed byte literals;
- byte classes with inclusive byte ranges;
- Unicode scalar classes expanded to canonical valid-UTF-8 byte-range paths;
- concatenation and ordered leftmost-first alternation;
- finite greedy or lazy repetition, unbounded repetition whose body consumes
  at least one byte, and a capture-free normalization for greedy `(A*){m,}`
  plus greedy-inner `(A?){m,}` when the outer repeat is greedy (or is lazy
  with `m = 0`) and `A` is one positive-width literal or class;
- every pinned absolute, LF and CRLF line assertion plus every ASCII and
  Unicode word assertion; and
- capture-node erasure only when the operation planner declares a
  capture-free output contract.

It explicitly rejects capture-sensitive operations and unbounded repetition
unless its body has `minimum_len() == Some(n)` for `n > 0` or it matches the
normalization above. The normalization removes capture wrappers only under the
capture-free operation contract and emits the equivalent positive-width
`A*`; its inspection and graph emission are charged to the same work limits.
Other nullable (`Some(0)`) and every unknown/empty-language (`None`) body
minimum remain rejected: `None` is not treated as a non-nullability
certificate. The restriction is required because K0's generation
deduplication does not in general prove ordered nullable-loop priority
(`(?:|a)*` and `(?:a|)*` select different spans in Rust regex). There is no
fallback that silently changes those semantics.

## Operation-aware HIR facts

The additive `facts` module derives conservative, typed facts from canonical
Rust HIR before an operation planner selects a backend. It distinguishes an
empty language from a nullable one; publishes checked width, complete finite
languages, positioned required-substring alternatives and assertions; records
Unicode scalar/UTF-8-width properties; and retains source-ordered capture facts
with `Never`, `Maybe`, `Always`, or fail-closed `Unknown` participation.
Determinization, one-pass and finite-language reduction certificates name the
selected output contract and their priority, greediness, empty-progress,
assertion-context and capture preconditions. `Unknown` and typed `Refused`
results are never positive facts.

Analysis uses a separate iterative census before construction. The census
preflights cumulative work, explicit stack occupancy, HIR nodes, retained,
temporary and peak logical bytes, and allocation attempts. Optional finite
language, required-string, assertion and deterministic-state publications have
independent typed refusal limits, so refusal leaves the remaining conservative
facts available. Reported construction actuals are checked against the
immutable prospective envelope. Every report carries the public semantic
algorithm and exact-accounting versions; consumers reject identities other
than the versions implemented by their linked `fre-lower`.

These facts begin at canonical HIR, not source syntax. In particular, expanded
Unicode classes cannot prove whether simple or full case folding produced
them, and HIR smart constructors can erase a capture nested only under an
outer exact-zero repetition. The API therefore reports source-schema and fold
origin as unavailable rather than reconstructing them. Every capture that
remains in HIR, including captures in impossible alternatives, stays in the
reported schema; capture-sensitive operations prevent erasure-based
reductions.

## Uniform capture-participation receipt

`lower_raw_general_with_uniform_capture_participation` pairs the unchanged
general capture-erased selector with an additive proof over the exact same
canonical `RustParsed` HIR. A positive receipt authenticates a nonzero minimum
match width and one source-independent count of participating user capture
groups. The theorem covers required and nested captures, equal-cardinality
alternatives, and repetition only when the participating capture set is
stable. Optional captures, unequal alternatives, nullable or empty languages,
and unstable repeated alternatives decline conservatively.

Proof work and the combined iterative task/result stack have independent hard
limits. Semantic declines remain successful selector lowerings; arithmetic,
allocation, limit, and invariant failures are terminal and typed separately
from incumbent lowering errors. Proof construction happens before selector
lowering, and the paired transaction checks that both paths observed the same
canonical capture census. It neither reparses source text nor changes the
selector `RawPlan`, `LowerStats`, route, or bytes.

## Bounded construction

HIR traversal is postorder over an explicit task stack. Repetition and Unicode
scalar-range expansion, fragment storage, Thompson edge patching, state/edge
emission, raw-table storage, and validator work all have checked arithmetic and
declared limits. Large finite repeats or expanded classes can therefore fail on
stack, work, state, edge, or storage limits before constructing an unbounded
graph. No lowering pass uses recursion or unsafe code.

An optional source-order-preserving prefix trie compacts direct alternations of
capture-transparent concatenations of byte literals and nonempty byte classes.
Sibling token sets must be exactly equal or disjoint; a partial overlap keeps
the ordinary Thompson lowering before graph publication. The proof uses a
fixed bounded source stack, fallible scratch arenas, and the same work and
automaton limits as the incumbent path. This includes the two-member byte sets
produced by ASCII case folding without recognizing any source-text recipe.

Unicode scalar ranges are partitioned with `regex-syntax`'s pinned
`Utf8Sequences` iterator. Each resulting one-to-four-byte sequence becomes a
concatenation of byte-range states, and the sequences form an alternation.
Those paths accept exactly canonical encodings of scalar values in the HIR
class: invalid, overlong, truncated, and surrogate encodings have no path.
The iterator's private range stack is bounded by the fixed UTF-8 width and is
precharged conservatively for every input scalar range; every yielded sequence,
emitted branch, state, edge, patch, and requested graph allocation remains
covered by the lowering work and automaton quotas.

The lowering work meter includes task dispatch and insertion, fragment and
patch-list movement, possible vector relocation, state/edge emission, edge
patching, and every final CSR table item. Each linear move is precharged before
it runs; allocator implementation internals are outside the unit definition,
while requested storage is separately preflighted and fallibly reserved.

`LowerStats::erased_captures` is the source HIR's count of distinct explicit
capture annotations. It is intentionally not multiplied when a finite repeat
emits several copies of the same annotated subexpression.
`LowerStats::normalized_nullable_repetitions` separately records each
certified nested nullable repetition removed before graph emission.

Edge order is semantic data: earlier alternation branches have higher
priority, and loop-versus-exit ordering represents greediness. Assertions are
emitted as original-haystack assertions, so a ranged search does not reinterpret
its range as a new haystack.

## Test layers

Integration tests exercise the full `fre-syntax -> fre-lower -> fre-automata`
path, priority and greediness, explicit nullable-cycle rejection, ranged
assertion context, resource failures, and a 20,000-term concatenation on a 128
KiB native stack.
An exhaustive small-alphabet differential suite compares supported expressions
with the explicit Rebar profile: `regex` 1.12.4, `regex-automata` 0.4.14 and
`regex-syntax` 0.8.11 with their independently packaged source receipts.

## Limitations ledger

- This crate lowers `RustParsed` HIR only. It does not implement the RE2 parser
  surface or own the facade's charged persistent-representation limit.
- Unicode scalar classes compile to valid-UTF-8 byte paths. Unicode word
  assertions decode at most one scalar on each side and classify it with
  the pinned UTS#18 Perl-word table. Invalid UTF-8 is exact non-word context.
- Every pinned absolute, LF, CRLF, ASCII-word and Unicode-word assertion is
  emitted as its own typed edge.
- `RustParsed` HIR does not retain a high-level builder's separately configured
  runtime line byte. This crate gives `StartLF`/`EndLF` their literal LF HIR
  semantics; the `fre` facade refuses non-LF profiles before selecting K0.
- Capture-sensitive search is unavailable. Capture syntax may be erased only
  after the caller selects the capture-free operation contract.
- Unbounded nullable or unknown-minimum bodies outside the explicitly proved
  capture-free atom normalization are rejected pending an ordered closure
  proof; finite nullable repetition remains acyclic and supported.
- The output is a portable K0 `RawPlan`/`Automaton`. This crate contains no JIT,
  AOT, SIMD, multi-pattern, replacement, or aggregate-iteration implementation
  and makes no claim yet about beating an upstream engine.
