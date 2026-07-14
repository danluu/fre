# Positive width is not an aggregate-progress proof

Regression pattern:

```text
(?:a+b|a)
```

On a haystack `a^N`, Rust leftmost-first semantics select `N` consecutive
one-byte matches. Nevertheless, an ordinary matcher started at boundary `i`
may have to inspect through EOF before it knows that the preferred `a+b`
branch fails and the shorter `a` fallback wins. Restarting the same search at
each selected end can therefore inspect roughly
`N + (N-1) + ... + 1 = O(N^2)` bytes even though every match has minimum width
one.

This separates two properties that must not be conflated:

- positive minimum width bounds the number of selected matches and guarantees
  cursor progress;
- finite decision horizon bounds how much future input is needed to finalize
  each selected match.

Only the second property (or finite maximum width, deterministic commit, or a
whole-operation retained-decision algorithm) can justify bounded-memory online
iteration without rescanning.

`late_priority_fallback_sequence_has_linear_whole_operation_certificate` in
`crates/fre-aggregate/tests/differential.rs` now preserves this case. For both
the full-table and reverse-row strategies it checks the complete upstream
sequence at `N = 64, 128, 256` and verifies that doubling input doubles the
incremental whole-operation work certificate. The directed differential
corpus also includes the pattern over empty, ASCII, and invalid-byte inputs.

The general aggregate recurrence solves all start boundaries together and
therefore remains `O(QN)` here. Any future streaming plan must reject this
shape unless a stronger analysis proves an equivalent complete aggregate
bound.
