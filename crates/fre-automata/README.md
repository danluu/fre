# fre-automata

This standalone crate is the first bounded portable automata layer for FRE. It
validates a manually lowered, prioritized Thompson graph into immutable
structure-of-arrays tables and supplies a safe, iterative, capture-free Pike
search floor.

It deliberately contains no regex parser, Unicode lowering, captures, JIT,
replacement, global iterator, or compatibility facade. Those layers must be
tested separately against independent oracles.

Key invariants:

- split states contain only ordered zero-width edges;
- consume states contain only ordered one-byte range edges;
- accept states have no outgoing edges;
- every index, table dimension, storage charge, scratch charge, and work charge
  is checked;
- `K0Workspace` exposes a fixed, auditable layout for repeated calls: its
  backing vectors are fully initialized once, never grow during search, and
  report allocator-visible retained capacity;
- one-shot calls remain available and report cold allocation/initialization,
  while reusable calls split their constant logical reset work from transition
  work and report zero per-call allocation;
- workspace shape mismatches and per-call scratch limits are errors rather than
  implicit resizing;
- logical thread lengths are reset before every invocation, including after an
  earlier resource error, and the generation table is cleared with an explicit
  setup charge before its counter could wrap;
- each state is admitted at most once per input boundary, terminating epsilon
  cycles without recursion;
- a pending match discards only lower-priority paths, while higher-priority
  paths continue to implement greedy ordered semantics;
- no later unanchored start is introduced after a pending match exists;
- assertions use the original haystack even for a ranged search; and
- positive Unicode word boundaries decode at most one complete scalar of at
  most four bytes on each side, classify it with the pinned UTS#18 Annex C
  table, allocate nothing, and never match inside malformed or partial UTF-8;
  and
- unsafe Rust is forbidden for the entire crate.

`Automaton::conservative_work_bound` certifies total charged work for a cold
one-shot call. `conservative_reused_work_bound` includes the worst-case rare
generation-table reset, while `conservative_transition_work_bound` isolates the
automaton loop. These are logical, deterministic charges, not wall-clock
deadlines. One charged assertion-edge inspection covers the fixed-width UTF-8
decodes and bounded lookup in the immutable Unicode word table.

Run its isolated tests with:

```console
cargo test --manifest-path crates/fre-automata/Cargo.toml
```
