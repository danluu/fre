# Public direct AOT Count benchmark

This package is causal plumbing for the exact-singleton direct Count-v3
candidate. It contains only generated public literals. The compiler build
script fails closed unless every width selects one coherent implementation:
the incumbent ordinary-entry Count loop or the authenticated direct Count-v3
tail. The executable independently checks every native result against a
scalar non-overlapping oracle and the ordinary, non-AOT `fre::AggregateBuilder`
Count operation before timing.

Build the identical harness commit in clean baseline and candidate worktrees
with separate target directories. The current causal pair is baseline
`bb84cb599` and candidate `ea995db90`; the latter differs by the forward-ported
direct Count-v3 optimization.

```sh
CARGO_TARGET_DIR=/tmp/fre-count-baseline-target \
  cargo build --release \
  --manifest-path tools/aot-direct-count-benchmark/Cargo.toml

CARGO_TARGET_DIR=/tmp/fre-count-candidate-target \
  cargo build --release \
  --manifest-path tools/aot-direct-count-benchmark/Cargo.toml
```

Run a bounded preflight first. Output paths must be new. `--smoke` is the only
way to relax the frozen final-gate floor of 61 paired samples, four alternating
warmup pairs, and 200 ms per timed process.

```sh
python3 scripts/benchmark-aot-direct-count.py \
  --baseline /tmp/fre-count-baseline-target/release/fre-aot-direct-count-benchmark \
  --candidate /tmp/fre-count-candidate-target/release/fre-aot-direct-count-benchmark \
  --samples /tmp/fre-count-smoke.jsonl \
  --summary /tmp/fre-count-smoke-summary.json \
  --smoke --pairs 2 --warmup-pairs 0 --min-sample-ms 1 \
  --widths 1 --bytes 64 --scenarios negative
```

Omit the smoke/subset options for the complete matrix: widths 1, 2, 4, 8, 16,
and 32; 64 B, 4 KiB, 64 KiB, and 1 MiB; and negative, early, late, dense-decoy,
and self-overlap shapes. Each invocation is a fresh process. Cell parity
balances AB/BA order globally. The JSONL retains every calibration, warmup,
and measurement invocation, stdout/stderr SHA-256, parsed route and semantic
digests, plus every pair. The summary reports paired confidence intervals,
AB/BA strata, nanoseconds per Count call/byte, GiB/s, and every regressing cell.
