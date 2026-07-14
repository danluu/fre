# Model, recurrence and proof boundary

## Declared language

Let `U = haystack.len() + 1` be the original byte boundaries. The AST permits
empty, exact byte, any byte, `\A`, `\z`, ordered concatenation, ordered
alternation, and arbitrary nested capture-free repetition. `Repetition` has a
checked minimum, optional inclusive maximum, and greedy/lazy priority; it
therefore represents `*`, `+`, `?`, `{m}`, `{m,n}` and `{m,}`. The legacy
one-boundary `RepeatAtom` form remains part of the stable test corpus.

A zero-width child completion ends the current unbounded iteration attempt;
backtracking may still try later child alternatives. It is never normalized
away. Thus the admitted model retains the span distinction between `(?:|a)*`
and `(?:a|)*`, as well as nested forms such as `(?:a?)*` and `(?:a*)*`.

Checked validation bounds AST nodes, depth and generated states. Lowering uses
recursion only after the configured depth bound has passed. The compiler then
proves that Strategy A's graph of same-boundary edges is acyclic. A consuming
edge is the only possible generated edge back to a repetition entry. Finite
bounds are capped at 1,000 in the default policy and expanded under the
program-state limit; the semantic grammar is not silently narrowed on failure.

## Compiler Strategy A: zero/progress product

For every unbounded repeated child `C`, compile `C` as an isolated prioritized
fragment, then form a two-mode product. Mode zero means no byte has been
consumed in the current iteration; mode one means progress occurred. Epsilon,
assertion and split edges retain the mode. Every byte edge targets mode one.
Fragment acceptance in mode zero targets the repetition's outer continuation;
acceptance in mode one targets its loop entry. Greedy/lazy priority orders the
body entry and direct exit at that loop entry.

This construction preserves the complete ordered child graph. In particular,
if a preferred empty child reaches a continuation that later fails, ordinary
priority fallback can still reach a later consuming child alternative. The
zero-mode acceptance itself never loops.

Required finite copies are ordinary fragment copies. Optional finite copies
are acyclic ordered splits. An open range is its required prefix followed by
the progress-product star. Nested unbounded products may multiply generated
states; the exact transformed `Q` is checked against `max_program_states`
before execution. No rejected transform is reported as admitted.

## Prioritized continuation recurrence

The compiler produces `Q` continuation states:

- `Match` returns the current boundary;
- `Byte(b, q)` consults state `q` at the next boundary when the byte matches;
- `AssertStart/AssertEnd(q)` consults `q` at the same boundary when true;
- `Split(high, low)` selects `high` if it succeeds, otherwise `low`.

For boundary `i`, let `V[i,q]` be failure or the selected end boundary. Rows
are evaluated from `U-1` down to zero. Within a row, a reverse topological
order of the same-boundary graph evaluates every dependency before its parent.
Consequently the recurrence has no fixed-point ambiguity.

### Subset theorem

Assuming Rust's capture-free leftmost-first semantics are ordered Thompson/
backtracking priority with a no-progress repetition guard, `V[i,entry]` is the
selected anchored end at `i`.

Proof sketch: use reverse induction on input boundary and topological induction
within one boundary. The deterministic instructions follow immediately.
For `Split`, the induction hypothesis says whether the preferred continuation
has a successful path and gives its selected end; ordered semantics takes it
exactly in that case. Every graph cycle crosses a byte edge, so the reverse
input induction is well founded. The checked compiler rejects a graph that
violates this premise.

For unanchored search at cursor `c`, choose the least `i >= c` with a successful
entry value. After emitting a nonempty match, set `c` to its end. When the next
selected match is empty at the preceding end, discard that selected match,
advance one byte, and search again; importantly, do not try its lower-priority
alternative at the same boundary. Induction on emitted matches gives the same
whole sequence as Rust's operation wrapper.

The upstream differential test is independent evidence for the semantic
assumption. It is not a substitute for extending this theorem when the syntax
grows.

## Compiler Strategy B: explicit guarded-state recurrence

`GuardedRegex` compiles each unbounded repeat to `SaveProgress(r)`, the complete
ordered child, and `CheckProgress(r)`. The save records the attempt's starting
boundary. At the check, a greater current boundary takes the loop edge and an
equal boundary takes the outer continuation. A lesser or inactive value is an
internal error. This raw graph may contain a syntactic epsilon cycle, but the
guard makes its loop edge semantically consuming.

The recurrence key is `(pc, i, g)`, where `g` is the vector of saved starts.
For `R` guard registers, each digit is a boundary or an inactive sentinel and
is encoded in radix `U+1`. The fully preflighted table contains:

```text
guard_space = (U + 1)^R
cells       = Q * U * guard_space
```

An explicit tri-state DFS/memo solver follows preferred children first. A
configuration is evaluated once; seeing `VISITING` again is a rejected
semantic cycle, not a fixed-point guess. Memo and maximum solver-stack storage
are reserved before work, and the complete conservative bound is checked
before any result is published.

This independently compiled strategy agrees on the generalized exhaustive
corpus, but its one-guard admission already grows quadratically with `U` and
multiple guards are exponential in `R`. It is therefore a valuable semantic
cross-check and falsifies itself as the general production representation.

## Executor 1: full suffix/priority DP

Materialize all `Q * U` values, then walk entry values monotonically. At most
two transition checks occur per state evaluation and at most `2U` root probes
occur under empty suppression.

- semantic work: `O(Q U + Z)`;
- random-access storage: `Q U` words;
- output work: `Z` spans;
- latency: offline table construction before the first span.

The implementation uses checked cell/byte arithmetic, preflights the
conservative whole-operation work limit, fallibly reserves the complete table
and output capacity, and never falls back to repeated search.

## Executor 2: packed whole-operation decision log

Keep only the current and next `Q`-word rows. At every split/boundary record
whether the preferred edge succeeded; record one entry-success bit per
boundary. After the reverse pass, scan root bits forward and replay only
selected paths.

Let `S` be the number of split states. The exact checked sizes are:

```text
decision_bits = S * U
logical_bits  = decision_bits + U
logical_bytes = ceil(logical_bits / 8)
resident_log  = ceil(logical_bits / 64) * sizeof(u64)
random_words  = 2Q
```

A replay cannot revisit a state at one boundary because the same-boundary
graph is acyclic. Selected nonempty spans do not overlap, and empty/adjacent
suppression creates at most linear additional replay attempts. Nonempty paths
visit at most `2N` state-boundary groups (span bytes plus one boundary per
match), emitted empty paths at most `U`, and suppressed empty paths at most
`U`. The admitted conservative replay bound is therefore `4QU`; construction
is `O(QU)`, so total semantic work is `O(QU + Z)`.

This prototype's log is packed but resident and randomly indexed during
forward replay. It demonstrates the whole-operation state and memory/work
tradeoff; it does **not** prove the stronger two-pass sequential-store lean-log
construction proposed in the architecture report. Its latency is offline and
the input remains borrowed until replay completes.

## Executor 3: reverse-sequential fixed-row log

The reverse DP naturally produces boundaries in descending order. Write one
fixed record per boundary containing `S` split choices and one root-success
bit. Aggregate replay visits input positions monotonically upward, so it can
consume those physical records strictly backward. It buffers one record to
permit arbitrary control-flow order among split choices at the same boundary.

```text
record_bytes = ceil((S + 1) / 8)
store_bytes  = U * record_bytes
random       = 2Q words + two record buffers
```

The prototype's reader rejects a position regression and accounts exact bytes
written and traversed. It uses a resident `Vec<u8>` as the store, so it proves
the access schedule rather than an external file/callback implementation.
`(?:a|b)|c` on `a` is a minimized layout witness: replay asks for the outer
split and then the earlier-compiled inner split at the same boundary. A
bit-at-a-time stream in compiler-rank order cannot satisfy that access without
buffering or seeking; one fixed row suffices.

## Oracle isolation

The oracle deliberately builds a fresh `Q * U` suffix table for every logical
search call. Dense results can therefore consume `O(Q U^2)` work. It is useful
because its operation structure mirrors upstream repeated iteration, but it
shares the compiler and recurrence with the candidates. The independently
implemented upstream Rust engine is therefore also mandatory in differential
tests. The oracle is never a candidate dependency or failure fallback.

## Admission and accounting

Before allocating an execution-sized buffer, each candidate checks:

- input boundaries and full-table cells;
- conservative total semantic work;
- random-access bytes;
- logical log bytes and separately word-rounded resident log bytes;
- fixed-row sequential bytes plus exact write/reverse-read traffic;
- guarded configuration count, memo/stack bytes and guard count;
- maximum result count and pre-reserved output bytes.

Table, log, row and output buffers use fallible reservations. Reports separate
state evaluations, transition checks, root probes, replay work, table builds,
random scratch, logical/resident log bytes, sequential traffic, guarded table/
stack use, output work/bytes and wall time.
Wall time includes preflight, allocation, execution and output construction.

## Stop/go conclusion

Go: preserve the progress-product compiler, all three bounded storage
executors, and guarded semantic cross-check. The next semantic extensions are
local byte assertions and captures, each requiring a new recurrence proof.

Stop: do not promote guarded state as production, describe fixed-row replay as
the paper's tighter lean bit log, or claim a complete Rust/RE2 iterator,
captures, Unicode, longest matching or production speed. Every extension must
update the recurrence key/proof and pass independent upstream differentials.
