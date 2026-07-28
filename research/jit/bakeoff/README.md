# AArch64 JIT actual-hardware bakeoff

This directory retains reproducible historical evidence for a deliberately
narrow V7 native backend. It is not evidence that FRE is the world's fastest
regex engine and is not qualification authority for the current composed
source.

At the exact historical Q source below, the V7 exact-literal leaf was qualified
only through the explicit opt-in `fre::QualifiedExactSearch`; no default
facade selected it. Its accepted historical envelope was limited to 16-byte
literals and a caller-declared amortization lower bound:

- at least 1,024 qualifying searches with windows of at least 64 KiB; or
- at least 64 qualifying searches with windows of at least 1 MiB.

That historical facade retained the portable literal plan and did not emit or
publish native code for other widths or under-qualified workloads. Calls
smaller than the declared window also stayed portable. Class-plus-suffix,
aggregate, and the 15-byte Sherlock cases were unqualified.

The measured Q commit is
`88e9c22c4ac382531bc1026ca0e25587905f5206`, tree
`131e38a4bfe5946bba6e994ee376ad239e1cca97`. The promotion commit must have
that exact Q commit as its sole parent and changes the isolated qualification
atom to `Qualified { bundle_sha256 }`, where the external canonical bundle
SHA-256 is
`de084ff0564acdb89889f28b9dcfddce9b6f0955a1b2aead30d75770039e0453`.
The Q execution source remains unchanged.

`qualified_exact_search_promotion.tsv` binds the historical Q revision/tree,
qualification source blobs, promotion-gate receipt, independent review,
findings, candidate binary, exact backend, and both workload tiers.
`verify_qualified_exact_search_promotion.sh` accepts a release only when the
promotion is the direct, closed-delta child of Q and a caller-supplied external
bundle passes the verifier materialized from Q itself. A descendant commit,
an extra source change, an arbitrary bundle constant, or a stale bundle fails
closed. The observed 34 MiB bundle is currently under
`/private/tmp/fre-jit-v7-q8-88e9c22c-bundle-r2`; that path is an ephemeral
provenance fact, not a runtime dependency or a durable artifact location.

The earlier 30/30 screen is invalid: qualified rows executed a `Span` facade
artifact but reported metadata from a separately emitted output-typed direct
image, omitted the artifact identity, and did not prove that measured call
counts met the declaration. No result in that screen authorizes production
routing. Sections explicitly marked historical retain old measurements only
as falsification history.

The measurements were taken on an Apple M5 Max running macOS arm64 with
Rust 1.93.0. Exact host, compiler, binary, fixture, and Rebar revision details
are recorded in each result directory's `environment.txt`. The historical
qualification used a clean Git revision plus a verified source-bound binary
receipt. Older retained result directories without Git metadata record their
workspace revision honestly as `unknown`.

The current composed source uses V8 as its default emitter policy, but the V8,
tag-10, tag-19, and tag-21 qualification atoms are all `Candidate`; legacy V7
is also hard `Candidate`. The historical V7 bundle and results in this
directory therefore authorize neither current production execution nor a
current performance claim.

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

This is 90 synthetic cells. Every stage is retained independently, including
search-only facade rows, build-plus-declared-workload amortization, and
explicit under-threshold portable refusal. Five additional processes time the
authenticated Rebar Sherlock fixture. The historical `verify_results.sh`
remains byte-for-byte compatible with old result directories;
`verify_qualification_results.sh` is the current route/artifact/workload
verifier.

The separate affected-shape matrix crosses 1-, 6-, and 15-byte literals with
the same outputs, sizes, and distributions: 135 cells and 7,425 rows per
current run.
It exists to detect short-input regressions hidden by the Sherlock corpus.

## Timing boundaries

Every synthetic process validates semantics before entering these timers:

| Engine | Stage | Included | Excluded |
|---|---|---|---|
| JIT | `plan` | literal/class input through validated typed Kernel IR and semantic identity | regex parsing, emission, publication, and search |
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
| experimental facade | `search` | actual routing check and selected portable/native calls; iterations meet the declared reuse count | construction and publication |
| experimental facade | `build_full_workload` | owner construction plus exactly the declared workload, reported amortized per search | nothing in the facade-plus-workload path |
| under-threshold facade | `search`, `build_full_workload` | the same boundaries with a declaration one call below admission | native emission and publication, which must not occur |

Iterations are fixed by haystack size, not calibrated from performance.
`raw.csv` retains total nanoseconds, iterations, a rolling checksum, the
single-call semantic value, image and mapping sizes, decoded instruction mix,
identity receipt, and cache accounting. `ranges.csv` reports the five-process
minimum, rounded mean, and maximum without discarding any raw sample.
Both synthetic and Sherlock serializers exactly match the 48-column V2
header. Sherlock rows explicitly report qualification state `not-applicable`
and bundle `none`.

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

## Invalidated historical v2 screen

The former canonical run used source commit
`0881191f9c7b0394f14c1d83a5766031ce3e21b1`. Its clean-tree build receipt binds
the Git tree, bakeoff lockfile, Rust toolchain, release binary path, and binary
SHA-256 before timing. `environment.txt` independently verifies that receipt
against the executable used by every process. The durable local artifact path,
hashes, and commands are in `research/jit/STATUS.json`.

The following numbers are preserved only as historical observations. They are
not qualification evidence because the facade rows had the artifact/output
metadata and workload-accounting defects described above:

| Result | Value |
|---|---:|
| Qualified wins versus fastest reference | 30 / 30 |
| Qualified mean / fastest-reference mean | 0.7933–0.8932 |
| Worst dense ratio | 0.8624 |
| Fully separated five-process ranges | 28 / 30 |
| Direct-JIT large-cell A/B wins versus original baseline | 30 / 30 |
| Direct-JIT new / baseline mean | 0.3777–0.8631 |

The two non-separated ranges are retained: 64 KiB unaligned `Span` overlaps by
1 ns at the range boundary, and 1 MiB dense `Span` had host noise. Their mean
ratios remain 0.7933 and 0.8549 respectively. There is no timing-based route
selection; size, literal width, and the declared reuse lower bound are the only
admission inputs.

Historical large-exact cold means across the 30 cells were:

| Stage | Range of five-process means |
|---|---:|
| validated Kernel IR plan | 379–519 ns |
| audited emission and image identity | 10,603–13,483 ns |
| strict-W^X publication plus first call | 36,645–62,700 ns |
| build, emit, publish, first call | 46,942–94,382 ns |
| production facade build plus first call, 64 KiB tier | 47,327–55,244 ns |
| production facade build plus first call, 1 MiB tier | 55,227–80,231 ns |

Measured portable break-even was 14–484 calls in that run. Earlier screens
observed a 626-call worst case. The experimental facade retains conservative
64-call and 1,024-call declarations for the 1 MiB and 64 KiB tiers, but
replacement evidence must execute and report those counts directly.

Current image sizes and instruction counts must be regenerated from the
source-bound binary; the old values predate the sealed search manifest and
block-local false-pair recovery. Hot identity access still reports its
precomputed identity without rehashing or allocation.

The optimized loop uses the pinned memchr frequency ranker for a lazy primary
and secondary byte pair, pointer induction with a hoisted vector bound,
`UMAXP`/`FMOV`/`CBNZ` reduction, block-local scalar recovery after false pairs,
and straight-line 16-byte confirmation.
The independent decoder and whole-operation auditor authenticate every
instruction, branch target, symbol, label, output store, and allowed vector
register before strict-W^X publication.

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

## Historical v1 bounded changes

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

## Historical v1 final result

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

- The invalidated direct-JIT comparison retained 61 losses: 54 long
  class-plus-suffix losses and seven short exact losses. Replacement runs must
  retain every loss again.
- Sherlock remains an unqualified 15-byte, 513-call aggregate workload:
  native direct mean is 48,000 ns versus 22,551 ns for portable FRE and 24,110
  ns for Rust regex.
- A native whole-operation count/aggregate kernel is still needed before
  aggregate routing. The temporary aggregate probe was also slower and was not
  promoted.
- General exact literals still need a proved-linear Two-Way,
  critical-factorization, or automaton leaf; the admitted pair-filter kernel
  remains bounded to short literal widths, and the experiment narrows it to
  the 16-byte case.
- No linked AOT comparator was available. The final artifact retains linked
  symbols, load commands, and disassembly, but these are provenance artifacts,
  not an AOT performance claim.

## Reproduction and verification

Run timing processes sequentially under the resource coordinator on a macOS
arm64 host with measured CPU headroom. Unrelated CPU work is not stopped;
another timing wave remains excluded. Release qualification uses a clean
source-bound build receipt:

```sh
/private/tmp/fre-control/resource-coordinator-v1/resource-coordinator.zsh \
  run-build jit-release --wait-seconds 30 \
  --build-dir /private/tmp/fre-jit-target -- \
  research/jit/bakeoff/build_bakeoff.sh \
  /private/tmp/fre-jit-target /private/tmp/fre-jit-build-receipt

/private/tmp/fre-control/resource-coordinator-v1/resource-coordinator.zsh \
  run-timing-wave jit-matrix --wait-seconds 120 -- \
  env FRE_BAKEOFF_BINARY=/private/tmp/fre-jit-target/release/fre-jit-bakeoff \
  FRE_BAKEOFF_BUILD_RECEIPT=/private/tmp/fre-jit-build-receipt/build-receipt.tsv \
  research/jit/bakeoff/run_matrix.sh /private/tmp/fre-jit-results

research/jit/bakeoff/verify_qualification_results.sh \
  /private/tmp/fre-jit-results 90
```

The adversarial matrix contains 54 cells spanning primary-dense/secondary-
absent, pair-dense/full-literal-absent, triple-dense/full-literal-absent,
early false pair with a distant match, binary, and natural-text fixtures.
V7 is not promotable unless both pair-dense and triple-dense groups are at
most 1.15x the faster reference:

```sh
/private/tmp/fre-control/resource-coordinator-v1/resource-coordinator.zsh \
  run-timing-wave jit-adversarial --wait-seconds 120 -- \
  env FRE_BAKEOFF_BINARY=/private/tmp/fre-jit-target/release/fre-jit-bakeoff \
  FRE_BAKEOFF_BUILD_RECEIPT=/private/tmp/fre-jit-build-receipt/build-receipt.tsv \
  research/jit/bakeoff/run_adversarial_matrix.sh \
  /private/tmp/fre-jit-adversarial

research/jit/bakeoff/verify_qualification_results.sh \
  /private/tmp/fre-jit-adversarial 54
```

For a clean alternating comparison, first build source-bound baseline and
candidate receipts at their respective clean commits, leave the workspace at
the candidate commit, then run:

```sh
/private/tmp/fre-control/resource-coordinator-v1/resource-coordinator.zsh \
  run-timing-wave jit-adversarial-ab --wait-seconds 120 -- \
research/jit/bakeoff/run_alternating_adversarial_ab.sh \
  /private/tmp/fre-jit-adversarial-ab \
  /private/tmp/fre-jit-baseline-receipt/build-receipt.tsv \
  /private/tmp/fre-jit-candidate-receipt/build-receipt.tsv
```

The adversarial runner writes
`fre-jit-alternating-adversarial-ab-v3`; the targeted runner writes
`fre-jit-targeted-alternating-adversarial-ab-v2`. Each timed invocation is
retained separately under `processes/`. `sequence.tsv` binds its unique
numeric PID, catalog cell, repetition, alternating variant, exact 40-digit
commit, and retained path. Verification follows each variant's own
name-resolved CSV header (the immutable baseline has 47 columns while the V2
candidate has 48), requires exactly one direct-JIT row per process, checks the
catalog order and alternating parity, and reconstructs both aggregate raw
files byte for byte. Older completion schemas and set-only sequence evidence
cannot qualify.

The retained targeted retry fixes one catalog-selected cell and alternates 15
fresh processes per variant:

```sh
/private/tmp/fre-control/resource-coordinator-v1/resource-coordinator.zsh \
  run-timing-wave jit-targeted-ab --wait-seconds 120 -- \
  research/jit/bakeoff/run_targeted_exact_exists_64k_ab.sh \
  /private/tmp/fre-jit-targeted-ab \
  /private/tmp/fre-jit-baseline-receipt/build-receipt.tsv \
  /private/tmp/fre-jit-candidate-receipt/build-receipt.tsv
```

`verify_v7_promotion_gates.sh` consumes the final main, 54-cell alternating,
and targeted outputs. It emits a deterministic receipt only when source,
binary, and build receipts agree; every qualified 64 KiB/1 MiB facade search
and full-workload mean beats `fre-kernels`; all 18 pair/triple dense ratios and
the targeted ratio are at most 1.15; and candidate/V7 evidence bindings pass.
Its `fre-jit-v7-promotion-gate-receipt-v1` output is a closed schema: every
source, tree, binary, build-receipt, state, backend, main, dense, and targeted
field occurs exactly once and meets its numeric gate. Sorted unique
`input_sha256` rows must non-emptily cover `main/`, `adversarial/`, and
`targeted/`; truncated, duplicate, unknown, or out-of-order fields fail:

```sh
research/jit/bakeoff/verify_v7_promotion_gates.sh \
  /private/tmp/fre-jit-results \
  /private/tmp/fre-jit-adversarial-ab \
  /private/tmp/fre-jit-targeted-ab \
  /private/tmp/fre-jit-v7-promotion-gate.tsv
```

The final evidence staging root has a closed layout. It contains exactly the
candidate and baseline executables under `binaries/`, their canonical build
receipts under `receipts/`, `gates/promotion.tsv`,
`reviews/independent.txt`, `reviews/findings.txt`,
`fixtures/en-sampled.txt`, `environment/host.txt`, and the complete `main/`,
`adversarial/`, and `targeted/` result trees. Its two-column
`kind<TAB>relative_path` input list must enumerate every managed regular file
and no other path. Every promotion `input_sha256` row must exactly match a
bundled `result` entry, so omitted, additional, or substituted files fail.
The review's findings hash must equal the canonical findings entry.

The maker copies that exact inventory once, rechecks the original, and replays
the complete promotion gate over the frozen copy using verifier scripts from
the exact Q commit. Replay uses the bundled executables, so it remains valid
after the source build paths disappear. The regenerated promotion receipt must
be byte-identical. Candidate and baseline executable hashes must agree with
their canonical receipts, the fixed promotion fields, and every in-tree copy
of those receipts. The verifier repeats the same frozen replay rather than
trusting aggregate receipt values, and both tools recheck the original
inventory after replay to reject concurrent mutation.

The maker also requires exactly one passing V7 promotion-gate receipt and one
`fre-jit-v7-independent-review-v1` receipt with result `pass`, the exact Q
revision/tree, scope `execution+evidence-schema`, a canonical
`/root/[a-z0-9_]+` `reviewer_task`, and a nonzero 64-digit
`findings_sha256`. Those seven review fields are exact and occur once. Both
maker and verifier reject symbolic refs, tags, abbreviated revisions,
candidate-as-baseline evidence, incomplete promotion receipts, and malformed
review receipts. The verifier also requires the external bundle hash:

```sh
research/jit/bakeoff/make_qualification_bundle.sh \
  /private/tmp/fre-jit-v7-bundle "$PWD" Q_REVISION \
  /private/tmp/fre-jit-v7-bundle-inputs.tsv

research/jit/bakeoff/verify_qualification_bundle.sh \
  /private/tmp/fre-jit-v7-bundle BUNDLE_SHA256 "$PWD"
```

Qualification is a two-phase operation. After committing only the promotion
delta as a direct child of Q, verify both the source relationship and the
external bundle:

```sh
PROMOTION_REVISION=$(git rev-parse --verify HEAD^{commit})

research/jit/bakeoff/test_qualified_exact_search_promotion.sh \
  "$PROMOTION_REVISION"

research/jit/bakeoff/verify_qualified_exact_search_promotion.sh \
  "$PROMOTION_REVISION" \
  /private/tmp/fre-jit-v7-q8-88e9c22c-bundle-r2 \
  "$PWD"
```

The source-only verifier mode is a regression-test aid and explicitly does
not authorize deployment. Release acceptance always supplies and fully
replays the external bundle.

Source correctness and strict gates used for the retained backend:

```sh
cargo fmt -p fre-jit-aarch64 -p fre-jit-runtime -- --check
cargo test -p fre-jit-aarch64
cargo test -p fre-jit-runtime -- --nocapture
cargo clippy -p fre-jit-aarch64 -p fre-jit-runtime --all-targets -- -D warnings
RUSTDOCFLAGS='-D warnings' cargo doc -p fre-jit-aarch64 -p fre-jit-runtime --no-deps
cargo fmt --manifest-path research/jit/bakeoff/Cargo.toml -- --check
cargo clippy --manifest-path research/jit/bakeoff/Cargo.toml --all-targets -- -D warnings
research/jit/bakeoff/test_exact_commit_contract.sh
research/jit/bakeoff/test_alternating_process_evidence.sh
research/jit/bakeoff/test_evidence_verifier.sh
research/jit/bakeoff/test_qualification_bundle.sh
research/jit/bakeoff/test_qualified_exact_search_promotion.sh \
  PROMOTION_REVISION
```

On shared hosts, pass each Cargo command through the repository resource
coordinator with the same task-private `CARGO_TARGET_DIR`. The exact final
commands and evidence manifest SHA-256 are retained in
`research/jit/STATUS.json`.
