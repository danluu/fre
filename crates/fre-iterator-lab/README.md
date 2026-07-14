# `fre-iterator-lab`

This is a research crate for FRE's highest-risk correctness/performance gate:
exact aggregate Rust-style iteration without repeated suffix search. It is not
a production regex engine and deliberately has no parser.

The public `Ast` is the executable subset declaration. It supports ordered
alternation and concatenation, exact/any bytes, empty expressions, absolute
start/end assertions, and arbitrary nested capture-free repetition. The
general `Repetition` variant covers `*`, `+`, `?`, finite/open ranges and
greedy/lazy priority. A checked progress-product transform preserves ordered
nullable branches while ensuring every generated loop backedge consumes. The
legacy one-boundary `RepeatAtom` API remains supported. Captures, Unicode text
semantics, local assertions and RE2 longest matching are not supported.

Four executors share the checked progress-product compiler but have different
storage and operation structures:

- `find_all_full_dp`: one word per program-state/input-boundary pair.
- `find_all_decision_log`: two word rows plus one packed bit per
  split/boundary and one root-success bit per boundary, followed by exact path
  replay.
- `find_all_sequential_row_log`: writes fixed decision rows in descending
  boundary order and reads them strictly backward while buffering one row.
- `find_all_oracle`: deliberately rebuilds the suffix table for every logical
  search. It is a quadratic-capable test comparator and is never a candidate
fallback.

`GuardedRegex` is an independently compiled comparison. It retains saved
iteration-start positions in its recurrence key instead of cloning zero/
progress modes. Its exact preflight is `Q * U * (U + 1)^R` cells, making its
multi-guard state explosion explicit.

Every large execution buffer is size/work preflighted and fallibly reserved.
Logical packed-log bytes, word-rounded resident log bytes, random-access
scratch and output reservation have distinct limits and counters.

See [`research/iterator`](../../research/iterator/README.md) for the theorem,
unsupported cases, retained counterexamples and scaling evidence.

```console
cargo test -p fre-iterator-lab
cargo clippy -p fre-iterator-lab --all-targets --all-features -- -D warnings
cargo run --release -p fre-iterator-lab --example scaling
```
