# Capture candidate model and bounds

Let:

- `Q` be immutable Thompson state count;
- `U = window.end - search_from + 1` be byte boundaries considered;
- `S = 2 × (user_capture_count + 1)` be capture slots;
- `H` be persistent history nodes actually created;
- `R` be aggregate iterator results/searches as separately reported.

The compiler emits ordered `Split`, byte-range, `Save`, assertion, epsilon,
match, and fail states. It expands finite counted repetition only after checking
`max_repeat_expansion`. Nullable unbounded star uses `(x+)?`; per-generation
instruction marking terminates every epsilon cycle without recursive
backtracking.

For one search, every instruction is processed at most once per generation.
Duplicate roots and edge targets are still work, so admission uses the simple
conservative certificate `state_visits <= 4 × Q × U`. The factor four covers
unique visits, at most two successor pushes per visited state, consuming roots,
and one newly injected unanchored start. All arithmetic is checked before the
search begins, and the exact counter is checked again during execution.

Inline-slot candidate:

- state work: `O(Q × U)`;
- logical capture copying: admitted at `<= 2 × S × 4 × Q × U`;
- live thread scratch: `O(Q × S)`, with three conservatively charged thread
  vectors plus the generation marks;
- winning canonicalization: `O(S)`.

Persistent-history candidate:

- state work: `O(Q × U)`;
- tag append work and retained history: `H <= 4 × Q × U`;
- live thread scratch: `O(Q)`;
- history arena scratch: `O(Q × U)` under the conservative admission bound;
- winner materialization: at most `H` history nodes plus `O(S)` slots.

Histories are stored in fallibly allocated 16,384-node chunks. Each chunk is
allocated once and never recopied; the outer chunk table is pre-admitted and
pre-reserved. This is required for the time certificate: one-node exact `Vec`
growth would preserve logical counters while permitting quadratic allocator
copying, so that representation is intentionally not used.

The two formulations have independent thread payloads and capture update/
materialization logic. They share only the immutable IR and boundary/resource
helpers. Neither calls the other, the Rust comparator, nor another engine as a
fallback.

Aggregate iteration is deliberately distinct. The laboratory implementation
repeats the bounded linear search, so its certified upper bound can be
`O(Q × N²)` even though every constituent search remains bounded. Before each
search, its per-search limits are reduced to the remaining aggregate budget;
it therefore cannot execute past total state, slot-copy, or history-node caps.
This formulation tests capture and empty-suppression semantics only. It is not
eligible as FRE's eventual non-quadratic production iterator.

Compiler caps are independently typed for AST nodes/depth, captures, counted
expansion, states, patch entries, compiler work, and immutable program bytes.
Executor caps are independently typed for state visits, slot copies, history
nodes, history reconstruction, scratch bytes, searches, results, and aggregate
totals. Refusal and allocation failure are observable errors, never no-match.
