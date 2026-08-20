# Frozen non-Rebar holdout v1

This directory is the first deterministic qualification corpus outside Rebar for the FRE portable facade. It answers a narrow question: for a frozen family of Rust-regex byte patterns and changing byte haystacks, does FRE return exactly the same leftmost-first result without a mismatch or internal fault?

It is deliberately visible, not sealed or blind. The raw suite, review schema, deterministic expansion, and exact counts are authenticated so a result cannot silently change the workload after measurement. Visibility still permits future overfitting; passing v1 is evidence for these frozen cases, not proof of general performance or full compatibility. Any suite change requires a new reviewed identity and regenerated digest sidecar.

## Frozen identity

- Suite ID: `fre-non-rebar-holdout-2026-07-14-v1`
- Raw suite SHA-256: `4107732fd57492bf8182dc805680abfdfb4e12c0bc5cc356ddda3de62ec75419`
- Raw schema SHA-256: `b2d791c78cebbd30961c0fa017d66d6e18cca019b92c49aa5af5f8d085076a80`
- Canonically expanded input SHA-256: `28c31631ab5c27926c19582aefdaf257fe53f4ee1263641fc31789f551ccacea`
- 19 case specifications, 169 input variants, 1,014 comparisons

`suite.json`, `schema.json`, and `digests.json` are all committed. Expanded records use tagged, length-delimited framing; every count and ordinal is canonical little-endian `u64`, independent of pointer width. Seeded generators use an explicit `u64` seed and a locally specified `SplitMix64` transition. No platform RNG, hash-map iteration, clock, or timing result affects expansion or correctness receipts.

The schema file is authenticated and its root identity is structurally checked. Runtime admission is implemented by Serde types with unknown-field denial plus explicit semantic and resource validation. The tool does not claim that it executes a general JSON Schema validator against the file.

## Semantic contract

The exact oracle is pinned `regex::bytes` 1.12.4 with Unicode disabled. It supplies Rust-regex leftmost-first `find`, `is_match`, and selected match end values. The candidate is the current `fre::PortableBuilder` auto plan. Deterministic receipts use the explicit default checked limits, and the same correctness pass separately verifies that FRE's ordinary Rust-compatible API returns the identical value without a caller-supplied search quota.

Each expanded input produces six receipts:

- hot reuse: one immutable candidate build per case, then three operations across changing haystacks;
- one shot: a fresh candidate build inside each `(case, input, operation)` receipt;
- operations: `find`, `exists`, and `selected-end`.

Receipt states are disjoint:

- `pass`: the candidate executed and exactly equaled the oracle;
- `unsupported`: an exposed unsupported feature or configured resource limit prevented execution;
- `fail`: both executed but the candidate value differed;
- `fault`: panic, invariant/range/arithmetic/allocation failure, or an error impossible for the admitted operation.

Configured work, scratch, construction, and syntax limits are `unsupported`, with stable resource reason codes. They are not mislabeled as implementation faults. Conversely, allocation failure and internal invariants remain faults. Unit tests exercise default versus one-below build/search limits.

Error stage matters: a build-only limit appearing from a completed plan's search path, or a forced-plan-only proof refusal appearing from this auto-plan adapter, is an impossible transition and therefore a fault rather than an unsupported result.

The strict gate rejects any `fail` or `fault` after writing the full report. `unsupported` remains a machine-visible coverage gap and is never counted as a compatibility pass.

`catch_unwind` can turn an unwinding panic into a fault receipt. The workspace release profile uses `panic = "abort"`; an abort terminates the process and cannot produce an individual panic receipt. Process supervision is therefore still required for production qualification.

## Correctness and performance are separate

Correctness output contains no clocks. Its receipt ordering, values, classifications, coverage maps, and receipt digest are deterministic for a fixed candidate and target. The report records target architecture, operating system, and pointer width explicitly; architecture-sensitive plan selection can therefore produce distinct, attributable receipts without changing the architecture-neutral expanded-input digest.

Optional performance output has a separate `fre.holdout.performance.v4` schema. It times equivalent ordinary APIs: FRE and Rust-regex both use `find` and `is_match` without a per-search work quota, and the selected-end diagnostic invokes `find` once and projects the match end on both sides. Both engines automatically retain implementation-owned, construction-bounded search scratch across hot calls; the caller does not construct an explicit session. The deterministic correctness report continues to use FRE's finite accounting APIs so plan and work receipts remain available outside the timing boundary, and it checks those finite results against the ordinary API before any timing.

The 2026-08-19 C9g diagnostic for automatic portable K0 scratch is summarized in [`docs/performance/automatic-portable-k0-scratch-c9g32-2026-08-19.md`](../../docs/performance/automatic-portable-k0-scratch-c9g32-2026-08-19.md). Raw timing samples remain external; the committed report contains only labeled diagnostic aggregates and reproduction hashes.

The follow-up C9g diagnostic for the general thread-owner workspace pool is summarized in [`docs/performance/owner-fast-pooled-k0-workspaces-c9g32-2026-08-19.md`](../../docs/performance/owner-fast-pooled-k0-workspaces-c9g32-2026-08-19.md). It compares the owner-fast pool with the preceding automatic mutex-backed pool and records the exact tested source separately from the feature commit.

The Rust-style ordinary-search follow-up is summarized in [`docs/performance/rust-style-ordinary-search-c9g32-2026-08-19.md`](../../docs/performance/rust-style-ordinary-search-c9g32-2026-08-19.md). It records the performance-v4 ordinary `find`/`is_match` boundary, the K0 holdout improvement, and the line-by-line Rebar grep cost exposed by removing the explicit benchmark session.

For operation timing, the manifest's warmup and measurement counts are repetitions **per expanded input**, not totals per case. Each phase executes complete repetition-major sweeps in ascending input-ordinal order, so every input receives exactly the same number of warmups and measurements. Build timing applies the same counts once per case pattern because construction has no haystack.

Each measured operation sample records `input_ordinal` and `repetition_index` alongside nullable `compile_ns` and `search_ns`. A hot-reuse sample has no compile duration, and a failed construction has no search duration. A completed search attempt retains its duration and machine-visible terminal state even when it reports an error. Compare engines only after matching `(case_id, mode, operation, input_ordinal, repetition_index)`; do not take separate medians over heterogeneous inputs and divide them, because the two medians can select different inputs. Rust-regex has no `selected_end` method, so that baseline performs one `find` and maps the match to its end; the report states this adapter explicitly.

Timing is diagnostic-only: there are no thresholds, no performance pass state, and `planner_feedback_permitted` is false. Host noise, CPU policy, allocator state, and architecture make these samples unsuitable as committed evidence. Do not tune the suite or candidate planner from this report and then describe the same v1 run as an untouched holdout.

## Frozen cases

| Case | Inputs | Purpose |
|---|---:|---|
| `literal-sherlock-changing` | 21 | positive/negative literal search from empty through long seeded haystacks |
| `literal-binary-ff-nul` | 4 | NUL and invalid UTF-8 literal bytes |
| `literal-fleet-english` | 12 | one disjoint multi-literal language |
| `literal-fleet-overlapping-prefix` | 9 | one overlapping-prefix multi-literal language |
| `mixed-concat-repeat-optional` | 18 | concatenation, class, repetition, optional suffix |
| `required-literal-class-suffix` | 15 | class-plus fixed-suffix shape |
| `forward-anchored-long` | 4 | absolute whole-haystack anchor semantics; despite its historical ID, its non-unique `E` boundary currently routes through K0 |
| `absolute-anchor-boundaries` | 6 | leading, trailing, and interior anchor negatives |
| `end-anchor-changing` | 12 | changing end-anchor positives and negatives |
| `empty-match-invalid-bytes` | 10 | empty matches on arbitrary bytes |
| `nullable-lazy-long` | 6 | lazy nullable selection on long input |
| `adversarial-overlap-positive` | 8 | overlapping unbounded alternatives with a positive tail |
| `adversarial-overlap-negative` | 8 | overlapping unbounded alternatives with a negative tail |
| `bounded-repeat-boundary` | 7 | below/at/above bounded-repeat limits |
| `ordered-alternation-short-long` | 6 | leftmost-first branch priority |
| `complete-byte-class` | 5 | complete byte class including NUL and `0xFF` |
| `decision-horizon-fallback-geometric` | 7 | `(?:a+b|a)` on geometric `a^N`, forcing EOF failure before fallback |
| `decision-horizon-primary-geometric` | 7 | the same adversary on geometric `a^N b` positives |
| `word-boundary-frontier` | 4 | historically unsupported boundary frontier, now admitted without changing the frozen case identity |

The two decision-horizon cases are labeled `suffix-restart-quadratic`: an implementation that restarts the higher-priority suffix decision at every position can turn a superficially positive-minimum pattern into quadratic work.

The phrases “literal fleet” in historical case IDs refer to alternatives inside one regex, not independent compiled-pattern fleets. The manifest now calls that covered dimension `multi-literal-languages`. Real 1/1K/10K+ pattern fleets, cache churn, and Zipf pattern rotation are explicitly future work.

## Declared limits

V1 is Rust-regex bytes, Unicode-off, capture-free, leftmost-first only. Captures and Unicode text are unsupported. RE2 Perl UTF-8, Latin1, POSIX, and longest-match profiles; replacement/split; streaming/vectored input; concurrency; JIT-denied operation; memory pressure; and production pattern fleets are future dimensions. AArch64 and x86-64 each require a receipt from real hardware; portable execution on one host does not satisfy the other.

These declarations are part of `suite.json` and therefore machine-visible and authenticated. They prevent a narrow current pass from being reported as full Rust-regex or RE2 syntax/API coverage.

## Run and integrate

From the workspace root:

```sh
cargo run --release -p fre-holdout -- authenticate \
  research/holdout/suite.json \
  research/holdout/schema.json \
  research/holdout/digests.json

cargo run --release -p fre-holdout -- run \
  research/holdout/suite.json \
  research/holdout/schema.json \
  research/holdout/digests.json \
  /tmp/fre-holdout-correctness.json \
  --performance /tmp/fre-holdout-performance.json
```

The second command writes correctness first, optionally writes separate timing diagnostics, prints exact status counts and the receipt digest, and exits nonzero if the strict mismatch/fault gate fails. CI should archive the correctness JSON even on nonzero exit. Run without `--performance` for the normative semantic gate.

`derive` prints a proposed digest sidecar for a consciously reviewed suite/schema revision. It is not part of ordinary qualification and does not overwrite committed files:

```sh
cargo run -p fre-holdout -- derive \
  research/holdout/suite.json research/holdout/schema.json
```

Tests cover digest golden framing, tamper rejection, deterministic reruns, exact current counts, one-below resource limits, strict gating, and equivalent timing series for both engines:

```sh
cargo test -p fre-holdout
cargo clippy -p fre-holdout --all-targets -- -D warnings
```

See `CURRENT.md` for the deterministic current coverage receipt. Performance samples are intentionally not committed there.
