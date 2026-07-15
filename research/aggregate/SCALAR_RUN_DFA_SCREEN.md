# Scalar-run deterministic aggregate screen

Status: source candidate. This document preregisters semantic, structural and
pointwise performance gates; it does not report wall-clock measurements or a
full Rebar result.

`PORTFOLIO_PROFILE=rust-bytes-unicode-scalar-root-plus-v1`

## Domain and construction seam

The auto planner selects this profile only for whole-match `compile`, `count`
and `count-spans` operations whose canonical Rust HIR, after transparent
capture nodes, is exactly one Unicode scalar class under an unbounded
repetition with `min=1`. Greedy and lazy repetition are separate retained
identities. The source spelling, parser/profile identity, operation, build and
run limits, greediness and kernel identity remain in the facade cache key.

Span materialization, forced continuation, anchors, bounded or nullable
repetition, literal repetition, raw byte classes and all other composition
retain their previous typed route. Existing exact-literal, finite-language,
K0, continuation and exact-one direct-Unicode selection is unchanged.

The mechanism is a fixed deterministic run automaton over the existing scalar
stream:

- greedy `CLASS+` accumulates the bytes in one maximal matching run and emits
  exactly one reducer event when the first outsider or end of input commits
  the run;
- lazy `CLASS+?` commits each matching scalar immediately; and
- invalid, overlong, surrogate, out-of-range and truncated UTF-8 advances one
  byte, never matches, and is an outsider that commits a preceding greedy run.

No set of live NFA alternatives is retained or visited at input boundaries.
The automaton has only the mode plus a pending greedy-run byte count. It emits
no spans and allocates no operation scratch.

## Correctness invariant

At each decoded scalar or invalid byte boundary, every byte strictly before
the current position has been classified once. For greedy execution,
`pending_run_bytes` is exactly the byte width of the maximal class-member
suffix since the last outsider; it is emitted once and cleared at the first
outsider or final transition. For lazy execution no run is pending and every
class member has already emitted one nonempty match. Therefore the reduced
spans are the same leftmost, non-overlapping sequence selected by canonical
`CLASS+` or `CLASS+?`. Because every match is nonempty, Rust's empty-match
progress rule is not involved.

Interior kernel windows decode only bytes inside the window. A scalar cut by a
window edge is invalid locally and cannot be matched across the edge. The
facade continues to use the complete haystack window. Capture annotations are
erased only for these whole-match reducers.

## Structural certificate

Let:

- `N` be input-window bytes;
- `Q` be canonical scalar ranges plus the constant repetition descriptor;
- `R` be retained non-ASCII ranges;
- `A <= 128` be ASCII scalars populated in the bitmap;
- `C <= N * (floor(log2(R)) + 1)` be charged non-ASCII range comparisons; and
- `T <= N + 1` be deterministic reducer transitions.

Construction work is at most `Q + A + R`, excluding checked allocator
internals. Persistent bytes are `size_of::<UnicodeScalarAggregatePlan>() +
8R`; construction scratch is the observed temporary range-vector capacity,
and construction peak is their checked sum. Execution performs at most `4N`
decode-byte checks, `N` membership tests, `C` range comparisons and `T`
reducer transitions. Thus its certified route is `O(N + Q + C + T)`, never
`N * Q`; for ASCII-only classes `C=0`, and for retained non-ASCII ranges `C`
is the existing direct-Unicode logarithmic membership term. Persistent space
is `O(Q)` and dynamic execution scratch is exactly zero bytes.

Preflight checks the complete upper bounds before traversal. Actual decode,
membership, range-comparison, reducer-transition, match, result, work and
scratch counters are published only after complete success. Every nonzero
new reducer limit has exact-limit success and one-below refusal coverage.

## N/2N/4N structural gate

For a fixed mixed ASCII/non-ASCII class and a unit containing member runs,
outsiders and malformed bytes, run the kernel at 8, 16 and 32 copies (the
registered `N/2N/4N` points). Require exact doubling of input advancement,
decode checks, valid scalars, invalid bytes, range comparisons, emitted
matches and greedy run flushes. Since each invocation has one final
transition, require `T(2N)-1 = 2*(T(N)-1)`. Dynamic scratch must remain zero at
all three points. This is a structural counter gate, not timing.

## Preregistered pointwise timing matrix

Do not aggregate these cells into a geomean and do not use their results to
recognize a benchmark. Each row expands to the three models `compile`,
`count`, and `count-spans`, and each model has two pointwise comparisons:
FRE/Rust regex 1.12.4 and FRE/RE2 2025-11-05. Use semantically equivalent
valid UTF-8 inputs for both references, report construction and hot execution
separately, and retain every loss.

| Cell family | Canonical shape | Input strata | Route expectation |
|---|---|---|---|
| affected-greedy-ascii | `[A-Za-z]+` | sparse, dense, alternating; 4 KiB/64 KiB/1 MiB | scalar-run greedy |
| affected-greedy-unicode | `\p{L}+` | Latin, Greek, CJK, mixed outsiders; 4 KiB/64 KiB/1 MiB | scalar-run greedy |
| affected-lazy-ascii | `[A-Za-z]+?` | sparse, dense, alternating; 4 KiB/64 KiB/1 MiB | scalar-run lazy |
| affected-lazy-unicode | `\p{L}+?` | Latin, Greek, CJK, mixed outsiders; 4 KiB/64 KiB/1 MiB | scalar-run lazy |
| affected-dotall-run | `(?s:.)+` and `(?s:.)+?` | one-, two-, three-, four-byte scalars; 4 KiB/64 KiB/1 MiB | scalar-run greedy/lazy |
| neighbor-root-class | `\p{L}` | same Unicode mixes | existing direct scalar |
| neighbor-literal-repeat | `abc+` | sparse and dense ASCII | continuation, unchanged |
| neighbor-anchored-run | `\A[A-Za-z]+\z` | full match and first-outsider miss | continuation, unchanged |
| neighbor-bounded-run | `[A-Za-z]{1,8}` | short and long runs | continuation, unchanged |
| neighbor-raw-byte-run | `(?-u:[A-Za-z]+)` | ASCII plus malformed bytes (Rust point only for malformed cases) | continuation, unchanged |
| neighbor-exact-literal | `needle` | sparse and dense ASCII | exact literal, unchanged |
| neighbor-finite | `foo|bar|quux` | sparse and dense ASCII | finite/literal portfolio, unchanged |

The malformed-byte semantic cases are mandatory differentials against Rust
bytes but are not assigned a false RE2-equivalence timing cell. The valid-UTF8
portion of the raw-byte row remains in both reference comparisons.

## Expected effect and open uncertainty

Affected reducers replace the continuation engine's certified
boundary-by-program-state table/row work and logs with one scalar traversal and
constant reducer state. This should reduce work and memory traffic on long
inputs, but no speedup is claimed before the matrix runs. Non-ASCII membership
still pays binary-search comparisons, tiny inputs still pay facade/report
fixed cost, and no authenticated full-corpus run has yet established how many
currently refused rows enter this exact generic HIR domain.
