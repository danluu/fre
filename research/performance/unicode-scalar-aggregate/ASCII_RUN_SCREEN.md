# Unicode scalar ASCII-run pointwise screen

Status: source-only preregistration. No timing in this worker.

`PORTFOLIO_PROFILE=supported-pointwise-core-a-r015`.

## Authenticated gap and supported census

The authenticated 236-pass frontier records 29 exact-literal aggregates, 143
continuation aggregates, 23 direct Unicode-scalar aggregates, two ordered
build-many aggregates, 19 continuation compile artifacts, two direct
Unicode-scalar compile artifacts, one ordered compile-many artifact, nine
portable grep rows, and eight selector/history capture rows. Count and span
timing, especially Unicode, remains an explicit promotion gate. The currently
checked-in evidence does not establish a complete pointwise win for any of
these strata.

| Supported stratum | Candidate change | Rust pointwise state | RE2 pointwise state |
| --- | --- | --- | --- |
| exact literal | unchanged neighbor | incomplete | incomplete where the authenticated row has RE2 |
| continuation | unchanged neighbor | missing candidate wave | missing where the authenticated row has RE2 |
| direct Unicode scalar | ASCII-run reduction affected | missing candidate wave | missing where the same profile/operation exists |
| ordered build-many | unchanged census control | missing candidate wave | missing where the authenticated row has RE2 |
| portable grep | unchanged census control | missing candidate wave | missing where the authenticated row has RE2 |
| selector/history capture | unchanged census control | missing candidate wave | missing where equal capture semantics exist |

Thus this work selects the direct scalar hot loop because its compile/count/span
fanout is authenticated and its pointwise gate is missing, not because a
favorable row was observed. Missing RE2 cells must remain marked missing; Rust
capture evidence cannot substitute for them.

## Mechanism and invariant

The direct Unicode plan now consumes each maximal ASCII run with one tight
bitmap loop and performs checked public-accounting updates once per run. Every
ASCII byte is still one valid scalar, one decode-byte check, and one bitmap
membership test. The unchanged general decoder handles every non-ASCII lead,
continuation, truncated encoding, overlong encoding, surrogate, out-of-range
encoding, and invalid byte. The selected plan, window, match order, count,
span sum, limits, persistent representation, and zero-scratch contract are
unchanged; the plan identity changes because the executable loop changed.

For `N` window bytes and `R` retained non-ASCII ranges, construction is
`O(Q)` and execution remains `O(N log(R + 1))`, with the ASCII portion `O(N)`.
Canonical disjoint `char` ranges live in the fixed 0x110000-scalar Unicode
alphabet, so the binary-search bound is at most 21 comparisons and the route
is certified near-`O(N + Q + T)` (`T` is the emitted count/sum reduction).
Persistent space is `size_of(plan) + 8R` bytes, construction scratch is the
fallible range-vector capacity already reported by `BuildAccounting`, and
execution scratch is zero. No input-boundary by pattern, query, state, or live
alternative product is materialized or scanned. Exact-literal, finite, K0,
continuation, ordered-many, portable grep, and capture/history dispatch are not
changed.

## Preregistered affected-neighbor matrix

Run only in the serialized timing lane. Use valid UTF-8 so Rust regex 1.12.4,
pinned RE2, and FRE have equal scalar semantics. For each cell report every
fresh-process pair, median, dispersion, allocations, plan ID, and structural
counters; do not summarize away a loss. `N = 4096` bytes, with exact `2N` and
`4N` repeats. Build once for hot execution; also report cold construction as a
separate cell. Test count and matched-byte span sum for every row.

| Route | Pattern | Position | Exact haystack unit | Rust | RE2 |
| --- | --- | --- | --- | --- | --- |
| direct scalar, affected | `\p{L}` | early | `A` then `0` through byte N | required | required |
| direct scalar, affected | `\p{L}` | late | `0` through byte N-1 then `Z` | required | required |
| direct scalar, affected | `\p{L}` | absent | `0` repeated N | required | required |
| direct scalar, non-ASCII neighbor | `\p{Greek}` | early | `α` then ASCII `0` padding | required | required |
| direct scalar, non-ASCII neighbor | `\p{Greek}` | late | ASCII `0` padding then `Ω` | required | required |
| direct scalar, non-ASCII neighbor | `\p{Greek}` | absent | ASCII `0` repeated N | required | required |
| exact-literal neighbor | `needle` | early/late/absent | ASCII padding with one or zero literal | required | required |
| continuation neighbor | `[a-z]+` | early/late/absent | ASCII digit padding with one or zero lowercase run | required | required |

The timing gate fails on any material affected or neighbor regression even if
the complete-matrix geomean improves. Separately retain the authenticated full
supported campaigns for ordered build-many, portable grep, and capture/history;
this focused matrix does not convert their missing comparator cells into
evidence.
