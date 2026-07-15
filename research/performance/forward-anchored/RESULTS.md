# Forward anchored source qualification

The portable start-only strategy remains
`anchored-class-suffix.asymmetric-scalar8-reverse32-inline.v1`. The new
absolute-end strategy is forced-only and is identified everywhere by
`anchored-class-suffix.absolute-end-fixed-suffix-first-bitset.v1`.

## Fixed-boundary source contract

For a valid full original-haystack window, `N = H.len()`, `M = S.len()`, and
`N > M`, the fixed verifier uses `p = N - M`, preflights `N`, compares
`H[p..N]` with `S`, and only after exact suffix equality visits each byte in
`H[..p]` at most once with the scalar bitset. Its certified upper bounds are
suffix `M`, prefix `p`, examined/work `N`, and zero prefilter, scratch, search
allocation, and fallback. A suffix mismatch retains those conservative upper
bounds but records zero prefix examinations.

Construction borrows the HIR literal until the kernel performs its one exact
copy. Exact caps admit; one-below suffix/work/persistent/peak caps refuse before
the copy. Layout and allocator failures are typed and do not retry or select a
different plan. The stored suffix has `capacity == len`; the plan certificate
uses actual capacity for persistent and peak accounting.

## Mutation ledger

The source tests bind all ticketed mutation families as follows:

| # | Mutant killed by |
|---:|---|
| 1 | forced start-only route and `aZx -> 0..2` facade witness |
| 2 | truncated `0..3` original-haystack window with zero accounting |
| 3 | nonzero `1..N` window with zero accounting |
| 4 | `N == M` suffix-only zero-accounting refusal |
| 5 | explicit `M = N + 1`, checked subtraction, and pre-access precedence |
| 6 | mismatch at every suffix offset |
| 7 | distinct first/last sentinels for `M=1,2,15,16,17,31,32,33,N-1,N,N+1` |
| 8 | outsider at every prefix position |
| 9 | outsider at byte zero |
| 10 | outsider at `p-1` |
| 11 | valid disjoint `S[0]` at exactly `p` |
| 12 | earlier suffix lookalike in the prefix, with no restart |
| 13 | bordered `aba` positive and every-offset tail mismatch |
| 14 | all 256 byte values as members, outsiders, and suffix sentinels |
| 15 | typed `FirstSuffixByteInClass` facade and kernel refusals |
| 16 | exact `N` admission and both one-below search limits |
| 17 | zero prefilter fields and at-most-`p` prefix actual counters |
| 18 | fixed stored identity plus source path with no search allocation/fallback |
| 19 | distinct runtime, cache, report, example, BASE, and ES8I identities |
| 20 | pinned Rust bytes exists/end/span differentials |
| 21 | borrowed-pointer and exact-copy/cap-precedence construction probes |
| 22 | suffix mismatch plus early prefix outsider records zero prefix visits |
| 23 | range, Pair, Triple, Quad, and arbitrary geometries all report Bitset |
| 24 | first-byte suffix mismatch still refuses under `N-1` before inspection |
| 25 | invalid, anchor-incompatible, and `N<=M` combined precedence witnesses |
| 26 | forced both-end/fixed versus forced start-only and Auto/old identities |
| 27 | complete `u8` normalization sweep |
| 28 | invariant `M`, `p`, and `N` upper bounds at every mismatch position |

The dedicated kernel theorem differential performs 3,211,068 comparisons.
The dedicated facade differential performs 52,416 pinned Rust-bytes span
comparisons and 157,248 operation projections across greedy/lazy repetition
and capture erasure. The broader pre-existing forward suites remain required
for final qualification.

## Disposition boundary

This document records source qualification only. It is not an independent
acceptance, benchmark, performance, integration, or promotion receipt. Guard
pages, complete affected-crate gates, strict Clippy, unsafe-lint enforcement,
clean provenance, and the predeclared code-size bounds must be recorded at the
exact final source head before an independent audit may accept it.
