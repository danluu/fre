# Retained semantic counterexample: adjacent empty suppression

For pattern `a|(?:)` and haystack `a`, Rust returns only `0..1`. A naive loop
that resumes at end `1` would also return `1..1`.

The operation wrapper instead observes that the newly selected match is empty
at the preceding match's end, discards that selected result, advances one byte,
and searches again. It does not ask the anchored matcher for a lower-priority
alternative at boundary `1`.

This behavior is represented in the monotone whole-operation walk shared by
all aggregate executors and has a directed regression in `tests/exact_sequences.rs`.
