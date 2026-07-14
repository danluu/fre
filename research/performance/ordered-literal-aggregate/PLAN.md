# Ordered finite-literal whole-operation reducers

Status: isolated kernel research. This work does not change the public facade,
the Rebar runner, plan selection, or qualification.

## Semantic scope

The input language is an ordered finite alternation of arbitrary byte strings.
The operation is either the number of successive non-overlapping matches or the
sum of their byte spans. Matching is Rust `regex::bytes` leftmost-first with
Unicode disabled. Pattern order, duplicates, invalid UTF-8, prefixes, and empty
alternatives are semantic inputs, not normalization opportunities.

Two deliberately different, operation-typed and non-`Clone` plans cover this
slice:

1. `OrderedLiteralCountPlan` and `OrderedLiteralSpanSumPlan` are the general
   correctness/resource floor. They accept empty alternatives and arbitrary
   literal widths. Their operation is linear in the haystack with exact
   transition accounting and fallibly reserved scratch. They are not a sensible
   default for ordinary sparse literal search: they touch every byte and the
   retained measurements show large losses there.
2. `PackedOrderedLiteralCountPlan` and
   `PackedOrderedLiteralSpanSumPlan` use the SIMD Teddy/Rabin-Karp searcher in
   pinned `aho-corasick` 1.1.4. They admit only nonempty languages satisfying
   `P <= 16`, `W <= 32`, and `T <= 512`. This path is research-only because its
   dependency performs infallible allocations while constructing a searcher.

There is intentionally no hidden fallback between these plans. A caller can
compare strategies before selecting one; a packed proof refusal cannot silently
change the algorithm or its resource contract.

## General reverse reducer

Let `best(i)` be the lowest ordered pattern ID among literals that start at byte
position `i`. Build an Aho-Corasick automaton over the reversed literals and
scan the haystack right-to-left. After consuming byte `i`, the automaton outputs
all original literals beginning at `i`; storing the minimum inherited output ID
therefore yields `best(i)`. Byte equivalence classes compress the dense table
without changing any transition.

The ordinary leftmost-first iterator has two states at a boundary:

- `I(i)`: a search starts initially at `i`;
- `P(i)`: the preceding match ended at `i`, so an empty match there is
  suppressed before advancing one byte.

For count, with `L` the length of `best(i)`, the descending recurrence is:

```text
no match:       I(i) = P(i) = I(i + 1)
empty match:    I(i) = 1 + I(i + 1), P(i) = I(i + 1)
nonempty L:     I(i) = P(i) = 1 + P(i + L)
```

For span sum, replace each added `1` by `L`; an empty match adds zero. At
`i = N`, an initial empty alternative emits once, while the progressed state
suppresses it. This is the empty-match behavior tested against `regex::bytes`
1.12.4.

Only positions through `i + W` are dependencies. A ring of
`min(N, W) + 1` entries cannot alias a live dependency: every dependency is at
positive distance at most `min(N, W)`, strictly below the ring length. The
operation performs exactly `N` DFA transitions, `N + 1` reducer positions, and
initializes exactly the retained ring length. All three are preflighted and
reported. Construction is iterative; all owned vectors use fallible reservation
before mutation, and their observed capacities are checked before traversal.

The tempting forward `AhoCorasick::find_iter(LeftmostFirst)` is not this floor.
For `[a^M b, a]` on `a^N`, each short match restarts a decision that can inspect
the long first alternative, yielding `Theta(N*M)` work. The reverse reducer's
transition counter remains exactly `N` for the same family.

## Bounded packed reducer theorem

Define:

```text
N = haystack bytes
P = number of patterns, P <= 16
W = maximum pattern bytes, W <= 32
T = total pattern bytes, T <= 512
m = minimum pattern bytes, m >= 1
E = floor(N / m)
C = E + 1 iterator calls, including the final no-match call
Q = (N + 1) + 36*C charged examined positions
```

Each match advances by at least `m`, hence at most `E` match events and exactly
at most `C` calls to `Iterator::next`. The pinned Teddy implementations scan at
most a 32-byte vector, retain at most three bytes of mask history, and may
revisit one terminal vector in every call. The per-call overlap charge is
therefore `32 + 3 + 1 inclusive boundary = 36`. Search intervals outside those
overlaps are disjoint because the next suffix starts at the prior nonempty
match's end. Short suffixes use the pinned rolling Rabin-Karp loop and fit under
the same larger charge.

At one charged position, each pattern belongs to one Teddy/Rabin-Karp bucket.
Across all candidate buckets there can be at most `P` pattern visits and at most
`T` compared pattern bytes. The accounting contract reserves another 64 units
for fixed mask/hash/control work per position and 64 units per iterator call:

```text
work <= Q * (T + P + 64) + 64*C
count <= E
span_sum <= N
scratch = 0
```

Since `P`, `W`, and `T` are absolute implementation constants, this is linear
in `N`; callers cannot raise those constants with permissive limits. All
arithmetic and limits are checked before iteration. `SOURCE_AUDIT.md` ties each
part of the theorem to the exact pinned source.

## Test boundaries

The kernel tests compare complete match sequences, count, and span sum with
`regex::bytes` 1.12.4, Unicode off. The general plan exhausts 258 ordered
languages (length one through three over six literals, including empty and
invalid bytes) against 121 haystacks. The packed plan exhausts 155 nonempty
ordered languages against the same 121 haystacks and also compares with the
general plan. Directed tests cover duplicate priority, prefixes, adjacent empty
suppression, arbitrary bytes, root/terminal/failure output priority, exact and
one-below resource limits, fixed-pattern and fixed-haystack scaling, and the
quadratic restart adversary.

## Integration decision

Do not promote either plan from this slice alone. The reverse plan is the
correctness/resource fallback for whole-operation literal reducers, but loses
badly on ordinary sparse input. The packed plan has promising SIMD results, but
its sparse differences are noise-scale and its construction is not yet
production-resource-safe. A production candidate needs a locally owned packed
builder with fallible allocation, a measured peak bound, qualification against
every admitted job, and selector thresholds derived from held-out workloads.
