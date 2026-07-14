# Capture semantics laboratory evidence

Status: exact research candidates for the admitted Rust byte-regex subset;
not facade-integrated and not a performance claim.

The comparator is exactly `regex = 1.12.4`, with default features enabled and
Rebar's explicit `logging` and `perf-dfa-full` features. The deterministic
generated core performs 14,508 complete canonical single-match comparisons:
39 generated base ASTs × 6 capture wrappers × 31 haystacks × 2 window layouts.
Every case is checked independently against both the inline-slot and
persistent-history formulations. A nested-repeat catalog, non-UTF-8 classes,
and directed cases bring the single-match total to 15,016 per candidate
(30,032 engine-to-oracle comparisons). Directed tests additionally cover:

- repeated captures and persistence of nested captures;
- unmatched groups and named/indexed records;
- ordered alternation;
- greedy, lazy, finite, unbounded, and nullable repetition;
- logical-window offsets and start/end assertions;
- Rust byte-regex aggregate empty-match suppression.

The aggregate catalog adds 20 complete capture sequences per candidate.

The test corpus is generated deterministically in
`crates/fre-capture-lab/tests/conformance.rs`; it has no random dependency or
ambient seed. The minimized counterexample found during development is kept in
`counterexamples/aggregate-empty-after-nonempty.json`.

`scaling.csv` comes from the checked logical counters emitted by the release
`scaling` example. It is not wall-clock timing. Both candidates visit the same
number of Thompson instructions. Inline slots have constant admitted scratch
for a fixed program/group count but perform slot-copy work. Persistent history
removes that copying and instead retains history nodes proportional to the
searched input before materializing only the winner.

See `MODEL.md` for the certificate and `UNSUPPORTED.md` for the exact boundary
and RE2 gate.
