# Public Rebar true-native census control

This directory contains a correctness census, not a benchmark. It answers two
separate questions without inspecting pattern or haystack contents:

1. Did the compiler emit and reproducibly link an AOT artifact?
2. Did the requested Rebar operation actually enter that artifact without
   calling any semantic runtime helper?

The first answer is never substituted for the second.

## Denominators

The canonical population is the de-duplicated public Rust/Rebar job set. The
current public corpus contains 344 jobs: 33 `compile` jobs and exactly 311
runtime jobs. The sealed plan refuses any other counts by default. Comparator
and first/steady replication produces a larger raw schedule-point population;
the plan seals those exact point IDs and their hash separately and never uses
that raw count in place of 311.

Every runtime job remains in the headline denominator. Unsupported models,
build/link failures, timeouts, missing receipts, wrong answers, helper-backed
execution, and failed controls are nonnative outcomes. The summary reports:

- authenticated native search cores / all 311 runtime jobs;
- strict whole-operation native jobs / all 311 runtime jobs;
- native search cores / successfully executed jobs (diagnostic only); and
- the raw runtime schedule-point denominator for comparison with older runs.

`count-spans` direct-entry iteration and per-line `grep` can authenticate a
native search core while retaining a Rust adapter outer loop. They are excluded
from the strict whole-operation numerator.

## Privacy boundary and static dry run

The controller accepts only files underneath an explicitly supplied public KLV
root. Paths containing a holdout or query-history component are rejected. The
plan stores public benchmark/job/point IDs, option flags, expected scalar
values, relative KLV paths, and SHA-256 identities. It never writes patterns,
haystacks, process output, stderr, or free-form failure text. Process streams
are represented only by byte counts and hashes.

Each schedule and its expected file digest must be named explicitly. Repeated
`--schedule` pairs may merge a primary public schedule and public supplemental
jobs; conflicting IDs fail closed. `--dry-run` validates the source freeze,
schedule identities, public path containment, KLV hashes, and the 344/33/311
denominators without writing output, invoking Cargo, building, running a test,
or executing a benchmark:

```sh
python3 tools/aot-rebar-runner/census/true_native_census.py plan \
  --schedule /public/control/schedule-timing.json \
  --schedule-sha256 EXPECTED_SHA256 \
  --public-klv-root /public/corpus/klv \
  --recorded-public-klv-root public-corpus/klv \
  --public-corpus-label public-rebar-CORPUS_ID \
  --source-dir /clean/fre-source \
  --source-commit EXPECTED_COMMIT \
  --source-tree EXPECTED_TREE \
  --target aarch64-linux \
  --features asimd,sve,sve2 \
  --dry-run
```

`--skip-klv-hashing` is available only with `--dry-run`; a sealed plan must
hash every public KLV byte stream. Remove `--dry-run` and add `--output` to
write the immutable `fre.aot-rebar.true-native-plan.v1` manifest.

## Later qualification run

Do not perform these steps while a timing holdout needs an idle machine. They
are documented so the committed controller is runnable later without another
design step.

Build every exact-adapter job twice in independent, empty target directories,
with the plan's commit/tree, target, feature set, public build KLV, locked
dependencies, and `CARGO_INCREMENTAL=0`. The final runner must export its
symbols to the dynamic symbol table (`-Wl,--export-dynamic` on ELF;
`-Wl,-export_dynamic` on Mach-O), because inability to arm a symbol is a failed
qualification, not permission to omit it. Preserve each runner and
`aot-rebar-artifact.o` separately.

Build `runtime_symbol_trap.c` as a shared library for the same target. The
source supports AArch64 (`BRK`) and x86-64 (`UD2`) on Linux and macOS. Then run
one receipt per exact-adapter job:

```sh
python3 tools/aot-rebar-runner/census/true_native_census.py qualify-job \
  --plan census-plan.json \
  --job-id PUBLIC_FRE_JOB_ID \
  --public-klv-root /public/corpus/klv \
  --primary-runner /build-a/fre-aot-rebar-runner \
  --replica-runner /build-b/fre-aot-rebar-runner \
  --primary-object /build-a/aot-rebar-artifact.o \
  --replica-object /build-b/aot-rebar-artifact.o \
  --trap-library /control/runtime_symbol_trap.so \
  --output receipts/PUBLIC_FRE_JOB_ID.json
```

Repeat `--primary-object` and `--replica-object` in component ordinal order for
a composite v3 runner. Its normalized provenance must match every supplied
object digest in both builds.

The controller requires identical runner/object hashes and normalized
provenance from both builds. It inventories all defined text symbols in the
final binary independently of `required_runtime_symbols`. Every executable
`fre_aot_regex_runtime_*` symbol except the explicit prepare/destroy control
plane is a semantic helper and is armed. Provenance-declared helpers must be a
subset of this independent inventory.

Three fresh processes authenticate each job:

1. The unmodified `--quiet` runner must exit zero after its independent Rust
   oracle comparison.
2. A copy with every semantic helper armed must still exit zero. The marker
   records every image-relative patch offset and before/after instruction
   bytes.
3. A fresh copy for each selected operation entry must exit with the dedicated
   trap status and name that exact entry. For `count` this is the reducer; for
   bulk `count-spans` it is Span-fill; for direct `count-spans` and `grep` it is
   the ordinary entry. Composite v3 provenance is normalized into a closed
   component list. `regex-redux` must publish exactly 15 component entries,
   per-component runtime-symbol lists, and program/object hashes; the
   controller runs 15 independent negative controls so a trap in the first
   stage cannot stand in for proof that the other 14 entries execute.

Thus a `RuntimeHelper` route fails phase 2. A mixed
`*WithRuntimeHelper` artifact is judged at the requested operation boundary:
an unused helper is harmless, while any helper actually reached by the job is
nonnative. Capture replay remains unsupported and therefore nonnative until an
exact adapter and a helper-free materialization path exist.

If a job cannot reach qualification, seal it rather than deleting it:

```sh
python3 tools/aot-rebar-runner/census/true_native_census.py record-failure \
  --plan census-plan.json --job-id PUBLIC_FRE_JOB_ID \
  --stage build --outcome timeout \
  --output receipts/PUBLIC_FRE_JOB_ID.json
```

Optional precomputed `--evidence-sha256` and `--evidence-bytes` fields can bind
an external log without letting the controller open or retain it. No diagnostic
contents enter the receipt.

Finally, summarize the complete population:

```sh
python3 tools/aot-rebar-runner/census/true_native_census.py summarize \
  --plan census-plan.json --receipts receipts --output summary.json
```

The summary retains all 311 runtime job IDs, every numerator ID, hashes of each
ID set, per-job dispositions, and a receipt-manifest hash. It cannot report
100% while any runtime job is unsupported, failed, timed out, missing, helper
backed, or lacks the claimed-entry negative control.
