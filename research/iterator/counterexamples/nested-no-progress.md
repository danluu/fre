# Retained semantic counterexample: nested no-progress guards

On haystack `a`, Rust's byte regex iterator selects:

```text
(?:(?:|a)*)*  -> 0..0, then 1..1
(?:(?:a|)*)*  -> 0..1
```

The outer repetition must observe whether the complete selected inner
iteration consumed, while the inner repetition independently preserves the
priority of its empty and consuming alternatives. One shared “nullable” bit,
language-level removal of epsilon, or an unguarded Boolean SCC fixed point
collapses these two programs incorrectly.

Strategy A gives every unbounded nesting level its own zero/progress product.
Strategy B gives each level its own saved-start guard digit. The directed test
`nested_empty_first_and_consuming_first_loops_stay_distinct` and the exhaustive
size-four corpus retain this counterexample.
