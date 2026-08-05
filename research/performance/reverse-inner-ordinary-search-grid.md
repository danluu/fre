# Reverse-inner ordinary-search proof and frozen validation grid

This document freezes the source-independent admission theorem and validation
grid before any timing. It is not derived from rebar, ripgrep, or another
holdout workload.

## Admitted language

The ordinary-search route may admit only a canonical Rust-bytes HIR equivalent
to one or more ordered alternatives of

```text
C+ Li C+
```

where:

- every `C+` is greedy, has minimum one, and has no finite maximum;
- every branch uses the same canonical class `C` on both sides;
- there are 1 through 16 nonempty literal alternatives;
- every `Li` is ASCII and every byte of `Li` is a member of `C`;
- captures may be transparent to whole-match search, but assertions, nullable
  branches, non-greedy repetitions, and every other topology are refused;
- `ClassUnicode` uses Rust byte-regex `utf8(false)` semantics: malformed bytes
  are barriers. A later widening may admit `ClassBytes` with byte semantics,
  but it must keep a distinct semantic identity.

The facade tries this route only after narrower direct one-run plans and before
finite/K0. Explicit `ForceK0` construction never tries it.

## Whole-match theorem

Let `R` be a maximal contiguous run of scalars in `C` inside the requested
half-open search window. Because each `Li` contains only members of `C`, a
branch is viable in `R` exactly when an occurrence of `Li` has at least one
`C` scalar before it and at least one `C` scalar after it. Greedy left and
right repetitions then cover all of `R`, so every viable branch has the same
whole-match span `R`. Branch priority and capture paths cannot change group 0.

The selected `find` span is therefore the first viable maximal run. `is_match`
is its existence, and `selected_end` is that run's end. Non-overlapping
iteration remains exact by repeating stateless windowed search at the prior
nonempty match end; maximal runs selected by one call cannot overlap a later
window.

`shortest_match` is intentionally different. Within the first viable maximal
run, its endpoint is the minimum over all viable literal occurrences of

```text
literal_end + width(next C scalar)
```

This is the first endpoint at which the language can accept. It need not be
the greedy selected span's end and it need not come from the first literal in
source order. Overlapping occurrences must be considered.

## Algorithm and accounting invariants

One monotone overlapping `memmem` stream per literal locates candidate runs.
For each earliest unseen candidate, bounded reverse/forward UTF-8 decoding
recovers its maximal run. Every literal is then searched from the strict
interior (`run_start + one scalar`) so overlaps such as `C = a`, `Li = aa`,
`R = aaaa` are not skipped. Streams advance to `run_end`; candidate runs are
disjoint. Thus scalar decoding is linear in source bytes and finder service is
bounded by the existing fixed-`k` `O(kN)` source-independent envelope.

All limits are derived and enforced before source access. Execution publishes
no partial result on refusal. The accounting identity binds the immutable
plan, selected operation, semantic mode, source ranges, literal count/bytes,
and source-order-sensitive literal fingerprint. Search retains no haystack or
cursor state, so cross-plan reuse and same-address haystack mutation cannot
affect correctness.

## Frozen synthetic differential grid

The validation owner must compare each admitted case against pinned
`regex::bytes::Regex` for `find`, `is_match`, `shortest_match`,
`find_at`/window search, `shortest_match_at`, `selected_end`, and full
non-overlapping iteration.

Axes (take the Cartesian product where meaningful):

- class: `[a]`, `[ab]`, `[a-z]`, `[^Z]`, `[a-z\u{100}-\u{17f}]`, and a
  non-ASCII-only class containing an ASCII admitted literal only when possible;
- literals: one and 2/4/8/16 alternatives; lengths 1, 2, 3, 8, 16; prefix,
  suffix, duplicate, and overlap relations (`a`, `aa`, `aaa`, `aba`, `bab`);
- topology: single concat, factored alternation, unfactored alternation, and
  transparent captures around roots/branches/repetitions/literals;
- run: absent literal, literal at first/last position (invalid), strict
  interior occurrence, multiple occurrences, overlapping occurrence, multiple
  viable alternatives, and multiple separated viable/nonviable runs;
- window: empty, full, every valid start/end pair for small haystacks, clipped
  through a run, clipped through a literal, and non-scalar-aligned byte bounds;
- encoding: ASCII, valid 2/3/4-byte scalars, isolated continuation bytes,
  truncated prefixes, overlong forms, surrogates, and invalid bytes on either
  side or inside candidate material;
- iteration: adjacent runs, separated runs, a prior match ending exactly at a
  later run, and duplicate alternatives;
- ownership: alternating calls across two unequal plans, same plan across two
  haystacks, and same allocation/address mutated between calls;
- resources: every individual build/search limit at exact bound and one below,
  arithmetic-overflow dimensions, 17 literals, empty/non-ASCII/out-of-class
  literals, unequal classes, reluctant/bounded/nullable repetition, assertions,
  and unsupported shape.

The route is rejected if any accepted cell differs, any refused shape is
admitted, actual accounting exceeds its pre-source upper bound, or `ForceK0`
selects it. Performance timing is permitted only after this envelope passes.
