# Prepared Exists-batch store-hoist experiment

Decision: do not promote the store hoist. Preserve the baseline emitter and
land the public benchmark, ABI clarification, and semantic regression tests.
The change is correct at the tested boundaries but does not establish a useful
performance improvement. No private corpus or sealed holdout was accessed.

## Source and scope

- Baseline: `a628dca374fc24a5a827825259aae482f8b526b4`, parent
  `44420fec0dab83ce964d9426deee1fc4d8b690d9`, with the public timing fixture.
- Rejected candidate: `4de773f1d4a80d53e9187899655da1a854ad44df`.
- Candidate branch: `codex/aot-general-perf-20260908-r1`.
- Baseline worktree: `/Users/danluu/dev/fre-aot-general-perf-baseline-20260908-r1`.
- Candidate/closeout worktree: `/Users/danluu/dev/fre-aot-general-perf-20260908-r1`.

The candidate moved the prepared Exists-batch completed-count store from the
per-descriptor loop to its common return on x86-64 and AArch64. The return value,
initialized result prefix, early argument checks, and late errors were preserved.
The final landing restores both production emitters exactly to the parent.

The common Rust harness and manifest are byte-identical in the two builds.
Both use standard release settings and serial `-j1` compilation. Three unrelated
objects (Fast Span, Optimizing Exists, and Optimizing Span) are byte-identical.
The Fast Exists text differs only in the batch wrapper; its preceding ordinary
and prepared search code is byte-identical. Generated registry differences are
the expected identity-suffixed symbols for the changed object.

## Measurement

The host was an ARM64 macOS machine; exact platform, binary hashes, Python
version, and load samples are retained in the logs. Each sample was a fresh
process. Only repeated prepared searches were timed; process startup, generation,
compilation, linking, and preparation were excluded. The endpoint authenticates
Fast / compiled-prepared / exists-batch-v1 / native-frozen-loop before timing,
and validates scalar and batch output against an independent literal oracle.
Batch size one takes the unchanged scalar path.

Two full, alternating AB/BA runs used 31 pairs each, targeting 40 ms then 50 ms
per sample. All 36 cells completed both times: 4,464 measurement processes,
zero endpoint/output failures, and no discarded samples. Co-tenancy was recorded,
not controlled. Calibration samples are retained but are not measurements.

A ratio above 1 favors the candidate. To combine runs with different calibration
counts, divide each elapsed duration by its iteration count, average all 62
per-batch times per arm, then divide baseline mean by candidate mean. Aggregate
ratios are equal-cell geometric means, not a production workload frequency model.

- All 36 cells: **0.999496x**.
- The 24 affected batch-size 8/64 cells: **0.996530x**
  (0.35% slower); 13/24 have nominal regressions.
- The 12 unchanged scalar controls: **1.005454x**.
- Early match, 64 descriptors, 64 KiB each: **0.962095x**, about 3.94% slower;
  both runs regress (0.959584x and 0.964638x).

These are point estimates, not significance claims. Variation in the unchanged
controls is further reason not to claim a causal speedup from this experiment.
This does not establish AOT versus non-AOT performance, Optimizing single-query
performance, or actual ripgrep fresh-process performance. It closes one proposed
prepared-wrapper optimization without enabling an application route.

| Scenario | Batch | Bytes/input | Run 1 | Run 2 | Pooled |
| --- | ---: | ---: | ---: | ---: | ---: |
| negative | 1 | 64 | 0.9984 | 0.9992 | 0.9988 |
| negative | 1 | 4096 | 0.9966 | 0.9969 | 0.9967 |
| negative | 1 | 65536 | 1.0008 | 1.0008 | 1.0008 |
| negative | 8 | 64 | 0.9882 | 1.0243 | 1.0060 |
| negative | 8 | 4096 | 1.0051 | 1.0016 | 1.0034 |
| negative | 8 | 65536 | 1.0043 | 1.0003 | 1.0023 |
| negative | 64 | 64 | 0.9877 | 0.9915 | 0.9896 |
| negative | 64 | 4096 | 0.9993 | 1.0073 | 1.0032 |
| negative | 64 | 65536 | 0.9986 | 1.0013 | 0.9999 |
| early | 1 | 64 | 1.0201 | 0.9977 | 1.0089 |
| early | 1 | 4096 | 1.0266 | 1.0227 | 1.0247 |
| early | 1 | 65536 | 1.0254 | 1.0013 | 1.0133 |
| early | 8 | 64 | 1.0020 | 0.9856 | 0.9937 |
| early | 8 | 4096 | 1.0167 | 1.0043 | 1.0106 |
| early | 8 | 65536 | 0.9969 | 1.0022 | 0.9995 |
| early | 64 | 64 | 1.0034 | 0.9992 | 1.0013 |
| early | 64 | 4096 | 1.0160 | 1.0081 | 1.0121 |
| early | 64 | 65536 | 0.9596 | 0.9646 | 0.9621 |
| late | 1 | 64 | 1.0232 | 1.0078 | 1.0155 |
| late | 1 | 4096 | 1.0040 | 0.9958 | 0.9999 |
| late | 1 | 65536 | 0.9985 | 1.0002 | 0.9994 |
| late | 8 | 64 | 1.0228 | 1.0126 | 1.0178 |
| late | 8 | 4096 | 0.9903 | 0.9818 | 0.9861 |
| late | 8 | 65536 | 0.9960 | 0.9992 | 0.9976 |
| late | 64 | 64 | 0.9914 | 1.0079 | 0.9996 |
| late | 64 | 4096 | 0.9802 | 0.9944 | 0.9873 |
| late | 64 | 65536 | 1.0007 | 1.0001 | 1.0004 |
| dense-decoy | 1 | 64 | 0.9912 | 1.0034 | 0.9971 |
| dense-decoy | 1 | 4096 | 0.9884 | 0.9933 | 0.9908 |
| dense-decoy | 1 | 65536 | 1.0208 | 1.0195 | 1.0202 |
| dense-decoy | 8 | 64 | 1.0328 | 0.9891 | 1.0105 |
| dense-decoy | 8 | 4096 | 0.9669 | 0.9652 | 0.9661 |
| dense-decoy | 8 | 65536 | 0.9748 | 0.9589 | 0.9669 |
| dense-decoy | 64 | 64 | 0.9792 | 0.9746 | 0.9769 |
| dense-decoy | 64 | 4096 | 1.0197 | 0.9738 | 0.9961 |
| dense-decoy | 64 | 65536 | 1.0451 | 1.0174 | 1.0310 |

## Validation and reproducibility

The candidate passed five focused compiler tests, eight thin-adapter batch tests,
and linked injected-error tests on ARM64 and x86-64 under Rosetta. The latter
exercise statuses 2, 3, 5, 7, 255, 256, 0x80000000, and UINT32_MAX at every
completed-prefix length 0 through 3, plus normal completion, empty batches,
top-level validation, and a late invalid descriptor. The final baseline emitter
passed all six focused compiler tests (including both linked error tests) and
all eight thin-adapter batch tests. The candidate-specific instruction-placement
assertion is omitted from the landing.

The first baseline release build was interrupted by SIGTERM and subsequently
completed. One default-stack compiler test invocation overflowed its thread stack;
rerunning with `RUST_MIN_STACK=33554432` passed. No benchmark compile or admission
failure was omitted. Existing compiler warnings remain outside this change.

Build instructions and the runner are documented in
`tools/ripgrep-aot-thin/README.md`. Focused tests use:

```sh
RUST_MIN_STACK=33554432 CARGO_PROFILE_DEV_DEBUG=0 cargo test -j1 -p fre-aot-regex --lib exists_batch -- --include-ignored --test-threads=1
RUST_MIN_STACK=33554432 CARGO_PROFILE_DEV_DEBUG=0 FRE_RIPGREP_AOT_PATTERNS_FILE="$PWD/tools/ripgrep-aot-thin/testdata/public-prepared-exists-batch.tsv" FRE_RIPGREP_AOT_VARIANTS=all cargo test -j1 -p fre-ripgrep-aot-thin --lib exists_batch -- --test-threads=1
```

The first command opts into the Rosetta test on ARM64 macOS; other hosts can
select the native linked-error test separately. Raw logs remain local at:

- `/Users/danluu/dev/fre-aot-prepared-batch-evidence-20260908-r1.jsonl`
  SHA-256: `6ba5873853631af2e98ea55d86c59c85a83447103854a37ab3b8399419adcc0b`.
- `/Users/danluu/dev/fre-aot-prepared-batch-evidence-20260908-r2.jsonl`
  SHA-256: `9f9ebfeeab71b3ca86e15c3685323d3d96d3581a36f4bb9b89c3e64928c4f3e1`.

Binary SHA-256s:

- Baseline: `59e0d18ba1c7b8d4122269f2eed0658bae9f187a5fc2b4c20d755b8c6363aed6`.
- Candidate: `1e56e571afc2357cd3894e3b2c7766208046d2a7ce56ff5ae7af8b3e4a849686`.

`results.json` retains all 36 cell aggregates and provenance. The rejected
candidate and original binaries are preserved for review; the landing makes no
production performance claim.
