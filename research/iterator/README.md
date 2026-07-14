# Exact aggregate-iteration laboratory

Status: the progress-product compiler now admits arbitrary nested capture-free
byte AST repetition, and four bounded whole-operation executors agree with the
Rebar-aligned Rust `regex` 1.12.4 comparator. An independently compiled
guarded-state recurrence agrees on the generalized exhaustive corpus while
exposing its larger state bound. This is positive evidence for the declared
subset, not proof for the full Rust or RE2 profiles.

Artifacts:

- [`MODEL.md`](MODEL.md): recurrence, theorem assumptions, bounds and stop
  conditions.
- [`UNSUPPORTED.md`](UNSUPPORTED.md): every case outside the result.
- [`scaling.csv`](scaling.csv): a reproducible release-mode counter/time run.
- [`generalization-scaling.csv`](generalization-scaling.csv): progress-product,
  guarded-state and reverse-sequential-log measurements.
- [`counterexamples/nullable-priority.md`](counterexamples/nullable-priority.md):
  why nullable loop alternatives cannot be erased or reordered.
- [`counterexamples/adjacent-empty.md`](counterexamples/adjacent-empty.md): why
  suppression belongs to the whole operation.
- [`counterexamples/sequential-access-order.md`](counterexamples/sequential-access-order.md):
  the one-row buffer required by reverse-sequential replay.
- [`counterexamples/nested-no-progress.md`](counterexamples/nested-no-progress.md):
  why nested nullable loops need independent progress state.
- [`crates/fre-iterator-lab`](../../crates/fre-iterator-lab): implementation,
  exhaustive differential tests and scaling assertions.

## Current evidence

The stable legacy corpus in `tests/exhaustive_small.rs` constructs exactly 666 ordered ASTs: 18 atomic or
repetition terms plus every ordered binary concatenation and alternation of
those terms. It checks all byte strings of length zero through three over
`{a, b, newline, 0xFF}`, exactly 85 haystacks. All 56,610 pattern/haystack
pairs produce identical complete span sequences in:

1. Rust `regex::bytes::Regex` 1.12.4 with Unicode disabled;
2. full suffix/priority DP;
3. the whole-operation decision-log prototype; and
4. the repeated-search oracle.

It now also checks the reverse-sequential row log. The comparator dependency is
exactly regex 1.12.4 with the workspace's Rebar-aligned default features plus
`logging` and `perf-dfa-full`; the tests explicitly use the byte API with
Unicode disabled.

`tests/exhaustive_general_repetition.rs` adds exactly 5,310 ASTs through size
four. Its grammar recursively generates all eight greedy/lazy `*`, `+`, `?`
and `{1,2}` forms plus every ordered binary concat/alt partition. The 21
haystacks are all strings through length two over `{a, b, newline, 0xFF}`.
All 111,510 pairs agree in the upstream comparator, progress-product full DP,
packed decision log, reverse-sequential row log, repeated oracle and the
independently compiled guarded-state DP. Together the stable and generalized
corpora cover 168,120 pattern/haystack pairs.

The compared sequence includes absolute anchors, greedy/lazy nullable loops,
malformed UTF-8 bytes, and Rust's suppression of an empty match adjacent to a
previous match. Directed regressions additionally cover lazy backtracking
through a nullable repetition.

`tests/scaling.rs` independently doubles input size, program size, and both.
The progress-product executors' state-evaluation counts are approximately 2×, 2× and 4×. On
the witness `.*b|a` over `a^N`, repeated-oracle state evaluations grow about
4× when only `N` doubles, while the bounded progress executors grow about 2×. These are exact
work-counter checks; the wall-clock column in `scaling.csv` is illustrative
and not a benchmark claim.

`tests/general_scaling.rs` repeats the three axes on generalized repetition.
Strategy A remains approximately 2×/2×/4× in exact state evaluations. Strategy
B's admitted table grows approximately 4× when input alone doubles with one
guard, matching `Q U (U+1)` and demonstrating why it remains a cross-check.
The sequential row log writes its exact declared store once and traverses no
more than that store during monotone reverse replay.

## Reproduction

```console
cargo test -p fre-iterator-lab
cargo run --release -p fre-iterator-lab --example scaling
cargo run --release -p fre-iterator-lab --example generalization
cargo fmt --all -- --check
cargo clippy -p fre-iterator-lab --all-targets --all-features -- -D warnings
RUSTDOCFLAGS='-D warnings' cargo doc -p fre-iterator-lab --no-deps
```

The oracle is intentionally isolated in `src/oracle.rs`. Neither candidate
imports it or invokes it on an error path.
