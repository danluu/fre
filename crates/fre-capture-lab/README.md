# fre-capture-lab

This is an isolated capture-semantics laboratory, not a production engine and
not a fallback. It currently proves a byte-oriented subset of the pinned Rust
profile (`regex::bytes` 1.12.4 with Rebar's default features plus `logging` and
`perf-dfa-full`). It is not integrated into the `fre` facade.

The modules deliberately separate concerns:

- `ast`: the admitted capture-aware byte AST;
- `compile`: checked admission and immutable prioritized tagged Thompson IR;
- `inline`: ordered Pike generations carrying inline slot vectors;
- `history`: the same IR executed with persistent tag-history nodes;
- `runtime`: conservative preflight bounds and canonical capture records;
- `profile`: versioned Rust and pending RE2 semantic identities.

Both executors are exact on the admitted subset and have no recursive or
exponential backtracking. They deduplicate an instruction within a byte
generation in priority order, and the compiler lowers nullable `x*` as
`(x+)?`, matching the Rust compiler's priority-preserving construction.
Unmatched groups remain `None`; a capture nested in a repeated expression
retains the last value that participated on the winning path.

`Program::compile_for` rejects the typed RE2 profile until the same corpus is
run against the pinned upstream C++ oracle. This prevents Rust evidence from
being silently relabeled as RE2 compatibility. The next RE2 step is a syntax
adapter into this AST, an upstream capture-record adapter, and a differential
gate for group numbering, names, anchors, range context, and repeated groups.

Run the qualification locally with:

```text
cargo test -p fre-capture-lab
cargo clippy -p fre-capture-lab --all-targets -- -D warnings
RUSTDOCFLAGS='-D warnings' cargo doc -p fre-capture-lab --no-deps
cargo run --release -q -p fre-capture-lab --example scaling
```
