# Search tag-30 qualification runner

This package is the pre-result, result-blind runner for the immutable tag-30
learned-continuation experiment and its separately frozen broad long-input
policy. Rebar, benchmark output, and campaign results cannot change literal
membership, fixture membership, sharding, routing, gates, or exclusions.

The contract SHA-256 is
`0ea6b3aefac2d31e67aae3acdef3b9f65d0b0fa91421a9ec5c3afe5517c9b2fd`.
Prepare the closed input set from a clean repository into a new directory:

```text
python3 prepare_inputs.py /absolute/repository /absolute/new-prepared-directory
```

The preparer creates four projections, the 808-object-candidate manifest, the
922-literal disposition manifest (including 114 structural refusals), the
projection summaries, and `prepared-inputs.json`. Two independent generations
must be byte-identical. For this contract the prepared-input file SHA-256 is
`e8a8c4a74a55372fb3651cc84de7ab58147f65f20b806812d5af4ae1580e5c85`.
All files are created new and made read-only.

## Two-stage private-family sealing

The selector-13 family is intentionally not checked in by this package. First
render an unsealed identity from a clean committed checkout:

```text
python3 render_identity.py discovery \
  /absolute/repository /absolute/prepared /absolute/new-discovery-identity.json
```

Build that identity separately on the local Apple AArch64 host and the C9g
Neoverse V3 AArch64 host. An unsealed build requires
`FRE_SEARCH_TAG30_ALLOW_UNSEALED_ARTIFACT_BUILD=1` and is object-only
discovery: do not execute the runner. Every linked build also requires:

```text
FRE_SEARCH_TAG30_QUALIFICATION_IDENTITY=/absolute/identity.json
FRE_SEARCH_TAG30_RUNNER_REVISION=<full-40-hex-HEAD>
FRE_SEARCH_TAG30_SOURCE_ARCHIVE_SHA256=<sha256-of-git-archive-tar-HEAD>
FRE_SEARCH_TAG30_PREPARED_INPUTS=/absolute/prepared/prepared-inputs.json
FRE_SEARCH_TAG30_OBJECT_CANDIDATE_MANIFEST=/absolute/prepared/object-candidates.json
FRE_SEARCH_TAG30_LITERAL_DISPOSITIONS=/absolute/prepared/literal-dispositions.json
```

The build receipt is `OUT_DIR/build-receipt.json`. It exposes the exact
neutral-inspected 20-field family tuple and all 808 object receipts plus 114
structural-refusal receipts. Review and SHA-pin both target receipts, then
make the reviewed copies read-only and create the authorization from the same
clean discovery checkout:

```text
python3 prepare_discovery_authorization.py \
  /absolute/repository /absolute/prepared \
  /absolute/discovery-identity.json <reviewed-discovery-identity-sha256> \
  /absolute/macos-build-receipt.json <reviewed-macos-receipt-sha256> \
  /absolute/linux-build-receipt.json <reviewed-linux-receipt-sha256> \
  /absolute/new-discovery-authorization.json
```

The preparer independently reconstructs the discovery identity, authenticates
the exact receipt schema and source/input class, and matches every object and
refusal receipt in order to the frozen prepared manifests. It creates one
read-only `fre.aot.search-tag30-qualification-discovery-authorization.v1`
envelope. The authorization is pre-result, private-only, non-production
evidence and pins the prepared/object/disposition identities, analyzer source,
discovery revision/source archive/runner source, and both target tuples.

Use the separate `tools/search-production-family-promotion` renderer to create
the exact target-conditional private rows. Commit only
`crates/fre-aot-static-runtime/src/search_support/private_rows.rs` as the
single direct child of the discovery revision. Then render sealed identities:

```text
python3 render_identity.py sealed \
  /absolute/repository /absolute/prepared \
  /absolute/discovery-authorization.json <reviewed-authorization-sha256> \
  /absolute/new-sealed-identity.json
```

The sealed evidence identity is exactly SHA-256 over the contract-declared
domain bytes followed by the raw contract, analyzer-source, and
discovery-authorization 32-byte digests. Sealed builds omit the unsealed
environment switch. The identity renderer rejects a dirty checkout, a
different parent topology, any promotion-commit path besides the private row
source, or a mutable/unreviewed authorization.

## Sharded execution

The contract fixes sixteen nonoverlapping ordinal shards for each projection.
Linux accepts 8 through 16 exact CPU IDs. The authenticated Mac17,7 Apple M5
Max host requires exactly six ordered worker labels, `12,13,14,15,16,17`,
corresponding to the six logical CPUs in its Super performance level. The
controller may execute shards in waves. Each worker keeps all six alternating
timing pairs for a row in one process and creates one immutable fragment:

```text
python3 run_shards.py (correctness|timing) CONTRACT \
  (universal|long-policy|diagnostic) PROJECTION HOST RUNNER \
  CPU0,...,CPUN EXISTING_OUTPUT_DIRECTORY
```

On Linux the runner hard-binds with `sched_setaffinity` and rejects a variant
unless both CPU endpoints equal the requested CPU. On macOS it installs
`QOS_CLASS_USER_INTERACTIVE` with relative priority zero and records a
`THREAD_AFFINITY_POLICY` request status of either success or
`KERN_NOT_SUPPORTED`; neither is represented as a hard binding. Before every
measured macOS variant it yields up to 100,000 times for a Super CPU. A variant
is accepted only when both endpoint samples are in the exact Super set.
Otherwise it is discarded solely by those endpoints and the same variant is
retried, up to 64 CPU-only retries. Every calibration-pilot and formal-variant
attempt records both endpoints, acceptance, and the retry count. Elapsed time
never controls retry. Each accepted formal variant must run for at least 400
ms. Guarded fixtures end at a `PROT_NONE` page and padded fixtures retain the
frozen mod-16 address.

Run the preregistered 30-cell `diagnostic` timing subset on each host before
formal timing, in separate diagnostic directories. It spans every width,
topology, window, outcome, learned-source kind, and mapping kind, but is never
promotion evidence. The formal analyzer accepts exactly 128 fragments: 64 per
host, comprising both correctness and both timing projections across all 16
shards.

Universal correctness calls every admitted V17 object directly, including
below the production floor. Long-policy correctness additionally checks the
automatic facade at its exact 65,536-byte floor. No timing bytes are opened
until every correctness fragment on both hosts authenticates; both hosts'
universal timing gates are then consumed before either long-policy timing
projection.

Universal timing is a mandatory mechanism prerequisite: all 3,078 cells on
each host must have median candidate/portable ratio strictly below 0.80.
Width/topology, width, topology, learned-source-kind, learned-source-relation,
and combined-host results are conjunctions of those cells; aggregate rescue is
forbidden and the result grants no production-policy authority.

Each complete 1,458-cell long-policy host projection independently requires
every cell ratio at most 1.05, at least 80% strict wins across all 8,748 paired
repetitions, and geometric means strictly below 0.80 overall and for every
width, topology, window, outcome, and learned-source-kind stratum. One failure
rejects the whole class; result-derived exclusions are forbidden.

Analyze the exact formal union into a new read-only receipt:

```text
python3 analyze_fragments.py CONTRACT \
  UNIVERSAL_FULL LONG_POLICY_FULL UNIVERSAL_TIMED LONG_POLICY_TIMED \
  EXACT_128_FRAGMENT_DIRECTORY NEW_ANALYSIS.json
```

Without `FRE_SEARCH_TAG30_QUALIFICATION_IDENTITY`, Cargo builds only a
selector-neutral test scaffold. Neither the unsealed discovery build nor the
final analysis grants production deployment authority.
