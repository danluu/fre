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
- finite greedy or lazy repetition, plus unbounded repetition whose body must
  consume at least one byte;
- every pinned absolute, LF and CRLF line assertion plus every ASCII and
  Unicode word assertion; and
- capture-node erasure only when the operation planner declares a
  capture-free output contract.

It explicitly rejects capture-sensitive operations and unbounded repetition unless its body has
`minimum_len() == Some(n)` for `n > 0`.
Both nullable (`Some(0)`) and unknown/empty-language (`None`) body minima are
rejected: `None` is not treated as a non-nullability certificate. The
restriction is required because K0's generation deduplication does not yet
provide a proof for ordered nullable-loop priority (`(?:|a)*` and `(?:a|)*`
select different spans in Rust regex). There is no fallback that silently
changes those semantics.

## Bounded construction

HIR traversal is postorder over an explicit task stack. Repetition and Unicode
scalar-range expansion, fragment storage, Thompson edge patching, state/edge
emission, raw-table storage, and validator work all have checked arithmetic and
declared limits. Large finite repeats or expanded classes can therefore fail on
stack, work, state, edge, or storage limits before constructing an unbounded
graph. No lowering pass uses recursion or unsafe code.

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
  surface or decide strict upstream constructor admission.
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
- Unbounded nullable or unknown-minimum bodies are rejected pending an ordered
  closure proof; finite nullable repetition remains acyclic and supported.
- The output is a portable K0 `RawPlan`/`Automaton`. This crate contains no JIT,
  AOT, SIMD, multi-pattern, replacement, or aggregate-iteration implementation
  and makes no claim yet about beating an upstream engine.
