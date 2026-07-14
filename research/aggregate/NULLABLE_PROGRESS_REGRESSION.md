# Nullable repetition progress-mode regression

This counterexample was found while graduating `fre-iterator-lab`. It is kept
even though the production construction now passes it.

Pattern:

```text
(?:(?:|a){1,2}?b?)*
```

Haystack bytes: `[0x62, 0x61]` (`ba`). Profile: regex 1.12.4 bytes API with
Unicode disabled. Exact canonical HIR:

```text
Repetition { min: 0, max: None, greedy: true,
  sub: Concat([
    Repetition { min: 1, max: Some(2), greedy: false,
      sub: Alternation([Empty, Literal("a")]) },
    Repetition { min: 0, max: Some(1), greedy: true,
      sub: Literal("b") }
  ])
}
```

Pinned Rust expected complete sequence:

```text
[(0, 2)]
```

The original single-loop zero/progress construction returned this sequence
for both `FullTable` and `ReverseSequentialRows`:

```text
[(0, 1), (2, 2)]
```

The independent guarded lab strategy returned the same wrong sequence. Thus
the fault was upstream of row ordering and upstream of the public adjacent
empty suppressor.

After consuming `b`, the next body attempt at boundary 1 first finds a
zero-width path. A single-loop product maps that success directly to loop exit,
which incorrectly outranks the lower-priority path that consumes `a`. Rust's
empty-loop guard depends on whether the repetition has already progressed.

The production compiler has separate initial and progressed loop entries. An
initial zero-width body match exits. After any earlier iteration consumed, a
zero-width body path maps to a failing sink, allowing lower-priority consuming
body paths to run before the loop exit. Finite mandatory prefixes are compiled
as one fragment whose aggregate zero/progress result selects the correct open
tail mode. The corrected program returns `[(0, 2)]` under both forced
strategies and remains same-boundary acyclic.

This is a semantic construction change, not a pattern special case.
