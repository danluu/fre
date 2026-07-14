# Persisted conformance inputs

`seeds.txt` pins deterministic generated corpus inputs. `counterexamples.tsv`
contains hand-minimized semantic gates. A row with `unsupported` is an open
production capability gate, not a conformance pass and not a claim that K0
currently returns the wrong value: the harness refuses to compile that case.

When a mismatch is found, minimize the AST and haystack while preserving the
full canonical record difference, add the reproduction seed and ordinal, and
retain the row after fixing it as a regression case. Never delete a row merely
because a planner begins selecting a different implementation.
