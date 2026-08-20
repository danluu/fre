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
- public `K0Workspace` constructors retain a fixed, auditable, address-stable
  layout: direct transition rows reserve their final capacity up front and
  initialize only as states become live; these workspace vectors never grow,
  while the automaton's separate immutable start-filter proof may still be
  allocated on its first use unless the caller prepares or warms it first;
- automaton-owned pools and adaptive search sessions admit the same finite
  layout as a hard ceiling but initially allocate only small direct forward and
  reverse cache seeds; reached state/item/row storage grows transactionally,
  and a refused growth attempt leaves the authoritative cache unchanged before
  execution continues through its canonical fallback;
- one-shot calls remain available and report cold allocation/initialization;
  reusable fixed calls report no cache-growth traffic, while adaptive calls
  separately report growth allocations, initialized bytes, retained deltas,
  and the transient old-plus-new scratch peak;
- setup `initialized_bytes` covers setup-phase writes, while demand-initialized
  transition rows and cache cells are charged to execution work;
- workspace shape mismatches remain errors; adaptive growth is permitted only
  within both the construction-admitted layout and the active call's scratch
  limit, while fixed workspaces never resize;
- logical thread lengths are reset before every invocation, including after an
  earlier resource error, and the generation table is cleared with an explicit
  setup charge before its counter could wrap;
- each state is admitted at most once per input boundary, terminating epsilon
  cycles without recursion;
- a pending match discards only lower-priority paths, while higher-priority
  paths continue to implement greedy ordered semantics;
- no later unanchored start is introduced after a pending match exists;
- assertions use the original haystack even for a ranged search; and
- unsafe Rust is forbidden for the entire crate.

`Automaton::conservative_work_bound` certifies total charged work for a cold
one-shot call. `conservative_reused_work_bound` includes the worst-case rare
generation-table reset, while `conservative_transition_work_bound` isolates the
automaton loop. These are logical, deterministic charges, not wall-clock
deadlines.

Run its isolated tests with:

```console
cargo test --manifest-path crates/fre-automata/Cargo.toml
```
