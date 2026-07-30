# Steady-state generalization gate

This is a compact, non-Rebar workload for comparing general byte-search
behavior. It was designed on FRE source
`8810cc1b4f409627b6bcc44756dfd2962b7cd6b7`. The corpus uses synthetic data
and pattern shapes selected independently of Rebar's benchmark definitions.

The matrix crosses:

- literal, alternation, fixed bounded, bounded and unbounded required-suffix,
  positive-loop, negated-loop, nullable, and no-literal shapes;
- late-reject and literal-decoy backgrounds for bounded filters, required
  suffixes, correlated alternation, and high-byte roots;
- LF, CRLF, ASCII-word, Unicode-word, Unicode-class, and Unicode-fold
  context;
- exact input sizes 15, 16, 17, 31, 32, 33, 63, 64, 65, 4093, and 262139
  bytes; and
- no-planted-match, sparse, and dense planting schedules.

All cases are byte searches. The high-byte root case intentionally generates
arbitrary non-UTF-8 bytes; every other generated haystack remains valid UTF-8.
The required-suffix literal decoy records a two-byte cyclic background phase,
which keeps every frozen exact length from ending immediately after
`TRAILER`; internal occurrences remain followed by the word byte `x`.

The byte operations are `is_match`, `find`, `find_at`, and complete
non-overlapping iteration. `session_setup` is a separate cold lane: regex
compilation is outside it, while construction of a FRE session or Rust cache
is inside it. Since setup does not consume the haystack, the catalog includes
one cold coordinate per case (`31` bytes, `absent`) instead of duplicating it
across all nine content coordinates.

## Fair steady-state state ownership

Every steady FRE point constructs exactly one `PortableSearchSession` before
timing and calls the session methods, including
`PortableSearchSession::find_iter`. Every Rust point constructs exactly one
`regex_automata::meta::Cache` before timing and calls `search_with` or
`search_half_with`. Complete Rust iteration uses the crate's public
`util::iter::Searcher` with that same caller-owned cache. Both states receive
one untimed warm operation. There is no hidden pool and no setup in a steady
lane. Rust syntax is explicitly configured with `utf8(false)` so the byte
comparator accepts the arbitrary-byte case without changing Unicode pattern
semantics.

`is_match` uses Rust's explicit-cache half-search in earliest mode, matching
the intent of its high-level existence API while avoiding that API's internal
pool. All other operations use leftmost-first full-span searches.

## Commands

From this directory:

```text
cargo run --release --offline -- catalog
cargo run --release --offline -- verify
cargo run --release --offline -- point \
  --case required_suffix --size 4093 --density sparse \
  --operation find --engine fre
cargo run --release --offline -- point \
  --case required_suffix --size 4093 --density sparse \
  --operation find --engine rust --iterations 10000
```

On the Arm evaluation host, add
`--features static-dispatch-arm-41-d84` before `--`. Dispatch separate point
processes externally to enforce the host utilization budget; this program
does not pin CPUs or use cgroups.

`verify` is clock-free and checks every steady operation against the Rust
engine with caller-owned caches. `catalog`, `verify`, and `point` all report
the plan identity and a deterministic FNV-1a checksum over the complete
matrix definition. A point also reports the untimed semantic digest, the
timed checksum, FRE runtime plan identity, and visible FRE session setup
accounting.

## Complete campaign

Build the binary first, run its clock-free verifier, then let the controller
freeze and execute a complete comparison:

```text
BIN=target/release/fre-steady-state-generalization
"$BIN" verify > verify.json
python3 controller.py run --binary "$BIN" --out RUN \
  --workers 96 --repetitions 4
python3 analyze.py --run RUN --out RUN/analysis.json
```

Use a smaller `--workers` value when the host budget is below 96 processes.
The controller rejects values above 96. It limits utilization only by the
number of concurrently dispatched point subprocesses: it contains no
affinity, pinning, NUMA, or cgroup mechanism.

The controller hashes the catalog, freezes and hashes a version-independent
deterministic schedule, and alternates randomized AB/BA engine order for each
point across repetitions. One controller worker executes one pair
sequentially in its frozen order, so `--workers` is also the maximum number of
simultaneous child processes. Each scheduled task produces one record
containing the parsed point JSON, status, return code, and captured stderr.
There are no retries or exclusions; any failed or missing task makes the
campaign incomplete.

The analyzer fails closed unless catalog, schedule, result, plan, semantic,
and steady checksum identities agree and every scheduled task is present. It
reports `Rust time / FRE time`, so values above one mean FRE is faster.
Pointwise ratios use per-engine medians across repetitions. Geometric means
are reported for the steady matrix overall and by family, size, density, and
operation; session construction remains a separate cold summary.
