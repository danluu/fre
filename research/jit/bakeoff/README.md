# AArch64 JIT actual-hardware bakeoff

This directory is reproducible evidence for one deliberately narrow backend,
not evidence that FRE is the world's fastest regex engine. The retained
`after-singleton-suffix-first` implementation still loses 107 of its 180
pointwise hot-search comparisons. It is **not promoted, qualified, or selected
by the FRE facade**.

The measurements were taken on an Apple M5 Max running macOS arm64 with
Rust 1.93.0. Exact host, compiler, binary, fixture, and Rebar revision details
are recorded in each result directory's `environment.txt`. The workspace had
no `.git` metadata, so the workspace revision is recorded honestly as
`unknown`; the release binary itself is SHA-256 authenticated.

## Fixed matrix

The main matrix fixes strategy before timing and never selects a plan from a
job name or a timing result:

- shapes: 16-byte exact literal and proved `[a]+` plus a 16-byte suffix;
- output contracts: `Exists`, `SelectedEnd`, and `Span`;
- haystacks: 96 bytes, 64 KiB, and 1 MiB;
- distributions: middle present, absent, dense false candidates, tail present,
  and deliberately unaligned present;
- five fresh, sequential processes for every cell;
- Rust `regex` exactly 1.12.4 and the read-only `fre-kernels` native plan where
  its public API supports the same first-match semantics.

This is 90 synthetic cells. Each process emits ten independently scoped rows,
so a complete main run contains 4,500 synthetic rows. Five additional
processes time the authenticated Rebar Sherlock fixture, producing 20 more
rows. `verify_results.sh` rejects missing cells or any stage without exactly
five process samples.

The separate affected-shape matrix crosses 1-, 6-, and 15-byte literals with
the same outputs, sizes, and distributions: 135 cells and 6,750 rows per run.
It exists to detect short-input regressions hidden by the Sherlock corpus.

## Timing boundaries

Every synthetic process validates semantics before entering these timers:

| Engine | Stage | Included | Excluded |
|---|---|---|---|
| JIT | `emit` | bounded native-image emission and precomputed image identity | publication and search |
| JIT | `publish_first_call` | fresh strict-W^X publication, audit, mapping, and the first typed call | IR build and emission |
| JIT | `build_emit_publish_first_call` | IR build/validation, emission, publication, and first call | nothing in the compile-to-first-result path |
| JIT | `direct_lease_call` | typed call through an already published lease | compilation, cache lookup, and publication |
| JIT | `cache_lookup_call` | resident bounded-cache lookup, lease, and typed call | compilation and initial publication |
| JIT | `identity_access` | O(1) precomputed image identity read | hashing, serialization, and search |
| Rust regex | `compile_first_call` | regex compilation and first search | nothing in its compile-to-first-result path |
| Rust regex | `search` | search through an already compiled regex | compilation |
| `fre-kernels` | `build_first_call` | plan build and first search | nothing in its plan-to-first-result path |
| `fre-kernels` | `search` | search through an already built plan | plan build |

Iterations are fixed by haystack size, not calibrated from performance.
`raw.csv` retains total nanoseconds, iterations, a rolling checksum, the
single-call semantic value, image and mapping sizes, decoded instruction mix,
identity receipt, and cache accounting. `ranges.csv` reports the five-process
minimum, rounded mean, and maximum without discarding any raw sample.

## Semantic authentication

Before timing each synthetic cell, the harness compares the typed native
result against all of:

1. the safe Kernel IR interpreter;
2. Rust regex 1.12.4;
3. the corresponding read-only `fre-kernels` plan.

The Sherlock fixture comes from pinned Rebar revision
`463d00f31887e84c38467805b9e3122c314b9521`. Both the fetch script and harness
verify 899,232 bytes and SHA-256
`0d40805f6d02c8fe02bd75945b98911891f707e8ecb939e018446858065d76ea`.
All engines agree on all 513 non-overlapping match spans and on the aggregate
checksum.

The JIT's Sherlock measurement is explicitly a **513-call loop over a
single-search `Span` ABI**. It is not a native count/aggregate kernel and must
not be represented as the final implementation strategy for Rebar's `count`
operation.

## Baseline falsification

The unmodified backend is retained under `results/baseline-unoptimized`:

| Hot direct comparison | Wins | Losses | Ties |
|---|---:|---:|---:|
| JIT vs Rust regex 1.12.4 | 16 | 71 | 3 |
| JIT vs `fre-kernels` | 6 | 82 | 2 |

Its worst families explain why this backend cannot be a default plan:

- exact dense false-first-byte input fell from the vector first-byte test into
  scalar full confirmation at every position and lost by about 36x;
- class+suffix bitset-tested every byte before confirming a suffix and lost by
  as much as 54x;
- the 15-byte Sherlock literal used no SIMD and the 513-call count loop took a
  mean 445,953 ns, versus 24,077 ns for Rust regex and 22,168 ns for
  `fre-kernels`.

`results/baseline-unoptimized/losses.csv` preserves every baseline loss.

## Retained bounded change

The retained code generator has two related changes:

1. every non-empty unanchored literal can scan 16 candidate starts with the
   already admitted NEON first-byte filter, including literals shorter than
   16 bytes;
2. literals of at least two bytes lazily apply a second last-byte vector mask.
   Blocks without a first-byte hit remain on the one-load fall-through path;
   only blocks with a first-byte hit load the last-byte column and intersect
   the masks with NEON `AND` before scalar confirmation.

If `x5 + 15 <= last_start`, every first-byte lane is a valid candidate start.
For literal length `M`, the same inequality proves the last-byte load spans
`x5 + (M - 1)` through `x5 + (M - 1) + 15`, all at or before the last searched
byte. Tails with fewer than 16 candidate starts use the scalar path. Actual
guard-page tests cover left- and right-adjacent inaccessible pages.

The unconditional two-position design is retained separately under
`results/after-two-position`: it fixed dense candidates but regressed ordinary
rare-first-byte scans by roughly 29--48%. The lazy design removes that broad
regression and is the retained variant.

### Complexity admission cap

Naive full confirmation at every candidate is only admitted when the repeated
confirmation payload is at most
`fre_jit_aarch64::MAX_REPEATED_CONFIRM_BYTES == 32`. Both exact literal and
class suffix emission return the typed
`EmitError::ConfirmationLengthLimit` above this cap. Start- or end-anchored
exact literals have one candidate, and start-anchored class kernels have one
class run, so those single-confirmation shapes may exceed 32 bytes.

The cap turns the repeated-confirm factor into an implementation constant; it
does not make this the general literal algorithm. A higher-level planner must
route longer unanchored patterns to a proved combined-input-linear Two-Way,
critical-factorization, or automaton kernel. Silent fallback inside this
backend is forbidden.

### Singleton-class suffix-first leaf

`class-suffix-theorem.md` is the admission proof for the new class leaf. The
emitter selects it only for the validated, unanchored `C+ S` CFG when `C` is a
singleton, the builder-proved delimiter satisfies `S[0] ∉ C`, and
`|S| <= 32`. Multi-byte classes retain the bitmap path and start-anchored
programs retain the existing single-run path; decoded-shape tests authenticate
both exclusions.

The leaf scans suffix candidates monotonically with first/last-byte NEON masks,
fully confirms the bounded suffix, then scans the one accepted singleton-class
run backward in 16-byte vectors. The disjoint delimiter makes suffix order the
same as whole-match start order and fixes the greedy end. Bounded confirmation
plus at most one backward scan gives `O(N + M)` combined-input work, constant
scratch, and constant-size emission. The theorem records the full leftmost-first
proof and every vector/scalar load-range obligation.

## Final measured result

`results/after-singleton-suffix-first` is the final main run for this slice:

| Hot direct comparison | Wins | Losses | Ties |
|---|---:|---:|---:|
| JIT vs Rust regex 1.12.4 | 33 | 50 | 7 |
| JIT vs `fre-kernels` | 30 | 57 | 3 |

There are therefore **107 retained losses**. Every loss, with both engines'
five-process ranges, rounded means, and the JIT/reference ratio, is in
`results/after-singleton-suffix-first/losses.csv`. No loss is excluded because
its absolute time is small.

Compared pointwise with the original JIT, the final main run is faster in 83
cells, slower in none, and tied in 7. Compared with the immediately preceding
lazy-pair result it is faster in 73, slower in 7, and tied in 10. Every changed
class cell is faster: its mean new/old ratio ranges from 0.0421 to 0.6429 and
averages 0.1512 across the 45 cells. All seven slower A/B cells are unchanged
exact-literal cells; their raw samples remain in the result directory.

The exact 1 MiB dense means fall from 740,579--742,660 ns across output types
to 36,581--40,892 ns, an 18--20x internal improvement. The references still
take about 20.4--20.8 microseconds, so the improved JIT remains 1.79--2.00x
slower on the workload it targeted.

Final Sherlock count ranges are:

| Engine/path | Five-process range (ns) | Mean (ns) |
|---|---:|---:|
| JIT direct 513-call loop | 239,095--246,179 | 243,731 |
| JIT cache lookup plus 513-call loop | 245,908--250,389 | 248,832 |
| Rust regex 1.12.4 count | 21,931--23,733 | 22,596 |
| `fre-kernels` count loop | 20,554--22,520 | 21,346 |

The Sherlock path is unchanged by the class leaf and remains 10.8x behind Rust
regex and 11.4x behind `fre-kernels`.

Final image sizes are independent of haystack size:

| Shape/output | Code bytes | Data bytes | Decoded instructions | SIMD instructions | Total mapping bytes |
|---|---:|---:|---:|---:|---:|
| exact Exists | 312 | 16 | 78 | 16 | 49,152 |
| exact SelectedEnd | 316 | 16 | 79 | 16 | 49,152 |
| exact Span | 320 | 16 | 80 | 16 | 49,152 |
| class Exists | 460 | 48 | 115 | 21 | 49,152 |
| class SelectedEnd | 464 | 48 | 116 | 21 | 49,152 |
| class Span | 468 | 48 | 117 | 21 | 49,152 |
| Sherlock Span | 272 | 15 | 68 | 11 | 49,152 |

The 49,152-byte mapping is three pages: two inaccessible guards and one
strict-W^X payload page. Identity receipts report zero bytes rehashed, zero
scratch, and zero allocations on hot access. Cache bookkeeping reserves
157,440 bytes under the fixed default policy.

## Remaining blockers

- The singleton class+suffix leaf is proved and materially faster, but it still
  loses 24/45 cells to Rust regex and 25/45 to `fre-kernels`. General byte
  classes require a separately proved vector membership representation rather
  than silently using this singleton path.
- General exact literals need a proved-linear Two-Way/critical-factorization or
  automaton fallback; the 32-byte pair-filter kernel is only a bounded leaf.
- A native whole-operation count/aggregate kernel is needed before comparing
  the single-search ABI fairly with Rebar aggregate models.
- The backend still has 107 pointwise losses and no RE2 qualification matrix in
  this slice. It is not ready for facade selection.

## Reproduction and verification

Run sequentially on an otherwise idle macOS arm64 host:

```sh
research/jit/bakeoff/run_matrix.sh research/jit/bakeoff/results/new-run
research/jit/bakeoff/verify_results.sh research/jit/bakeoff/results/new-run
```

The short-literal matrix is:

```sh
research/jit/bakeoff/run_short_matrix.sh research/jit/bakeoff/results/new-short-run
```

Source correctness and strict gates used for the retained backend:

```sh
cargo fmt -p fre-jit-aarch64 -p fre-jit-runtime -- --check
cargo test -p fre-jit-aarch64
cargo test -p fre-jit-runtime -- --nocapture
cargo clippy -p fre-jit-aarch64 -p fre-jit-runtime --all-targets -- -D warnings
RUSTDOCFLAGS='-D warnings' cargo doc -p fre-jit-aarch64 -p fre-jit-runtime --no-deps
cargo fmt --manifest-path research/jit/bakeoff/Cargo.toml -- --check
cargo clippy --manifest-path research/jit/bakeoff/Cargo.toml --all-targets -- -D warnings
```

`results/MANIFEST.md` identifies the canonical evidence directories, and
`results/manifest.sha256` authenticates their key raw and derived files.
