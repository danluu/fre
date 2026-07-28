# Tag-19 SVE ABI2 qualification and promotion

This directory defines the source-bound qualification contract for the
qualified exact-search facade's `Sve16V6` / backend-19 route. It does not
authorize legacy Search-v1 tag-19 images, and it does not offer standalone
tag-19 promotion.

The route emits direct AArch64 machine code through `fre-jit-aarch64`; LLVM is
not the regex compiler. The qualified facade publishes the audited image
through `fre-jit-runtime` and calls it only through
`SelectedEndRegisterV2`: haystack, length, window start, and window end in
`x0..x3`, with zero or the absolute exclusive match end returned in `x0`.
There is no `x4` result slot. The process contract is Linux AArch64,
ASIMD+SVE, homogeneous Arm implementer `0x41` / part `0xd84`; a callable
session requires the calling thread's SVE VL to be exactly 16 bytes.

All four checked-in JIT qualification atoms remain `Candidate`. Source,
producer, parser, or local test success is not qualification.

## Admission and run boundary

Do not build or time this campaign while a coordinator cutover fence is
active. After the controller publishes explicit live-helper GO and its exact
SHA-256, run on the declared host with the timing thread pinned to one CPU.
Other CPU work is not by itself a reason to wait when the admitted helper
reports sufficient headroom; do not kill unrelated work.

Bind every build to one exact Candidate commit/tree, source archive,
Cargo/rustc/rustdoc identities, complete toolchain and Cargo-registry
closures, the live resource-coordinator identity, its cutover receipt,
and profile:

```text
linux-aarch64-arm-41-d84-vl16-release-v1
```

The build receipt admits only target
`aarch64-unknown-linux-gnu`, `CARGO_INCREMENTAL=0`,
`RUSTFLAGS=-Ctarget-cpu=native`, and the workspace release profile
`opt-level=3,codegen-units=1,lto=thin,panic=abort`. Its two command fields
must be exactly:

```text
cargo build --locked --release --target aarch64-unknown-linux-gnu -p fre-jit-runtime --no-default-features --features sve-hardware-qualification --example tag19_selected_end_register_v2_qualification
cargo test --locked --release --target aarch64-unknown-linux-gnu -p fre --no-default-features --features qualified-exact-search-jit --lib --no-run
```

The build produces and retains two executable files with mode `0755`:

```text
artifacts/tag19-abi2-producer
artifacts/tag19-facade-qualification
```

The first is the release example
`tag19_selected_end_register_v2_qualification`, built with the default-off
`fre-jit-runtime/sve-hardware-qualification` feature. The second is the exact
`fre` library-test executable containing
`qualified_exact_search::tests::tag21_facade_qualification::tag19_driver`.
The build receipt binds both executable hashes. Copying a different binary
under either name invalidates the bundle.

## Correctness producer

Run `artifacts/tag19-abi2-producer` once with the source-bound build
environment and runtime run/instance/build-receipt identities. Retain only its
single newline-terminated row as:

```text
evidence/abi2-producer-v1.tsv
```

Its exact schema is
`fre-jit-tag19-selected-end-register-v2-qualification-v1`. A valid row proves
backend 19, target bits 3, deterministic ABI2 artifact identity, no
publication VL, session VL16, independent image audit, zero stores, forbidden
`x4`, 4,102 portable/KIR/native comparisons, twelve guard-page placements,
and d8-d15 preservation on immediate-match, long-absent, and late-match
control-flow paths.

Run the ignored automatic-facade receipt test from the same source-bound test
binary and retain only the single `fre-jit-auto-facade-v5` tag-19 row as:

```text
evidence/facade-v5.tsv
```

V4 sibling rows remain byte-stable for their independently versioned
consumers. They are not part of the tag-19 V5 receipt.

## Fresh-process facade performance

The raw CSV is:

```text
evidence/facade-performance-v5.csv
```

Generate its header through the tag-19 driver's `header` command. Then run the
driver's `run` command in one fresh pinned process for each cell, in this exact
order:

1. contiguous repetitions starting at zero, with at least three repetitions;
2. literals: `unique`, `repeated`, `alternating`, `natural`, `binary`,
   `rank-adversarial`;
3. sizes: `64k`, `1m`;
4. scenarios: `absent`, `late`, `homogeneous`, `near-miss`.

Each process emits exactly eight rows in portable/facade order for `build`,
`search`, `cold`, and `full`. Strip only the fixed
`FRE_JIT_TAG19_FACADE_ROW<TAB>` prefix. Do not average, filter, replace, or
discard rows. The producer records and rechecks `/proc/thread-self/status`
affinity around the timed region. All rows share the correctness producer's
run, instance, resource-coordinator, cutover, and profile identity.

The verifier reconstructs the complete matrix and rejects a cell assembled
from multiple PIDs or a PID reused for multiple cells. It independently
recomputes every semantic value and every search/cold/full checksum. For every
literal/size/scenario it computes exact candidate/portable ratios per
process, then one-sided upper bounds on the log-mean using the Bonferroni
per-cell alpha `0.05/48`. The verifier uses the upward-rounded df=2 critical
value `sqrt(458882/959)` for every process count of at least three, so the 48
cell bounds are simultaneous with at least 95% familywise coverage within
each stage. Both hot-search and full-workload maximum upper bounds must be
below 1.0. Cold cost remains retained, and every cell must break even within
its declared call count; the calculation counts the search already included
in the one-call cold measurement.

## Closed bundle

`qualification-bundle-tag19-abi2-v1.tsv` is the exact sorted manifest. Its
required inventory is:

```text
BUNDLE.sha256
qualification-bundle-tag19-abi2-v1.tsv
subject.tsv
artifacts/abi2-witness.tsv
artifacts/tag19-abi2-producer
artifacts/tag19-facade-qualification
verification/correctness.tsv
verification/performance.tsv
provenance/build-receipt.tsv
provenance/toolchain-closure.tsv
provenance/cargo-registry-closure.tsv
provenance/source-snapshot.tsv
provenance/source.tar.gz
evidence/abi2-producer-v1.tsv
evidence/facade-v5.tsv
evidence/facade-performance-v5.csv
evidence/review-findings.txt
```

Every manifest entry has a kind, nonzero SHA-256, exact positive byte count,
and canonical path. Every nonbinary file, including the manifest and
`BUNDLE.sha256`, is mode `0644`; both producer binaries are mode `0755`. The
bundle contains no unmanifested file or directory. `BUNDLE.sha256` contains
only the externally published manifest digest and a newline.

Each closure file is canonical sorted TSV: one exact `schema` row followed by
`entry<TAB>SHA256<TAB>bytes<TAB>relative-path` rows. Sizes are canonical
nonnegative decimals so empty physical files remain represented; cargo,
rustc, and rustdoc themselves must be nonempty. The verifier reparses both
files, rejects noncanonical POSIX path spellings, recomputes their SHA-256,
entry count, and declared byte count, and requires the toolchain closure to
contain `bin/cargo`, `bin/rustc`, and `bin/rustdoc` with hashes equal to the
build receipt's three executable hashes. The verifier cannot rehash external
toolchain or Cargo-registry files that are not in the sealed bundle; the build
producer and independent reviewer are responsible for materializing those
physical files and generating the canonical closure rows. This is the explicit
external provenance trust boundary.

The exact ordered receipt schemas live in
`verify-tag19-promotion-delta.sh`. In particular:

- the bundle manifest hashes every retained component; the subject directly
  binds all three raw-evidence hashes and both producer-binary hashes;
- correctness and performance directly bind their relevant raw evidence,
  build directly binds both binaries and both closure manifests, and the
  independent review directly binds all raw evidence and both binaries, so
  the complete receipt set collectively binds the same evidence graph;
- the build receipt binds the exact Cargo/rustc/rustdoc binaries, toolchain
  and Cargo-registry closure manifests, target, feature sets, code-generation
  environment, exact build commands, source archive/snapshot, resource
  helper, cutover receipt, profile, and ABI2 artifact;
- correctness equals the producer's exact 4,102 comparison count and PASS
  gates;
- performance values equal the verifier's raw-CSV derivation, not a
  separately trusted summary;
- the source snapshot and external witness bind the reviewed ABI2 source
  closure and exact four-Candidate root.

The independent review receipt is outside the resealable bundle and is pinned
by an externally published SHA-256. The verifier independently recomputes the
reviewed ABI2 source closure from exact Candidate Git blobs. The source
snapshot's broader archive-closure scalar remains an attestation of the
externally pinned archive by the build producer and reviewer; it is not a
second verifier-side materialization of every archive entry.

## Promotion

Run the exact `0755` verifier blob stored in the Candidate:

```console
research/jit/sve-hardware/verify-tag19-promotion-delta.sh \
  REPOSITORY CANDIDATE PROMOTED EXPECTED_TREE \
  EXPECTED_SOURCE_ARCHIVE_SHA256 EXPECTED_BUILD_RECEIPT_SHA256 \
  EXPECTED_MANIFEST_SHA256 /ABSOLUTE/TAG19_EVIDENCE \
  /ABSOLUTE/TAG19_REVIEW.tsv EXPECTED_REVIEW_SHA256 \
  VERIFIED_V8_BUNDLE_SHA256 composed-exact-union-delegated
```

The verifier rejects shallow history, replacement refs, grafts, non-direct
children, a changed running verifier, a noncanonical four-Candidate root,
source-closure drift, evidence mutation, legacy tag-19 schemas, and any
promotion delta outside the exact JIT atom (plus the separately coordinated
AOT atom when the top-level union owns that path).

Tag 19 can become `Qualified` only in the same direct child that retains an
independently verified nonzero V8 fallback digest. Tag 10 and tag 21 remain
`Candidate`. Use the top-level protocol in
`research/native-promotion/PROMOTION.md`; a delegate PASS is not composed
authority until that coordinator also verifies the complete union.
