# Retained semantic counterexample: nullable priority

Rust `regex::bytes` 1.12.4 on haystack `a` selects:

```text
(?:|a)*  -> 0..0, then 1..1
(?:a|)*  -> 0..1
```

Thus a capture-free compiler still cannot erase a nullable body alternative or
replace a nullable repeated body by its consuming language. Its position in
the ordered body changes the selected span. `RepeatAtom` preserves this order;
a zero-width branch exits the current attempt while leaving later alternatives
available if the continuation backtracks.

This counterexample is a directed test in `tests/exact_sequences.rs` and is
also covered by the exhaustive upstream differential.
