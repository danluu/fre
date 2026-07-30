# Optimizing Count-v3 compiled-Rebar runner

This standalone Cargo workspace has two deliberately disjoint build
authorities. `qualification-private` is the original formal, native-only
qualification runner; its request, observation, registry schemas, and private
handle types are unchanged. `production` is a post-promotion confirmation
runner. It can construct only source-authorized production handles, uses the
automatic production FRE facades, and refuses to retain a timing unless the
typed route is `AsimdAot` or `SveAot`.

The build script authenticates one frozen Rebar inventory, reconstructs every
fixed-policy exact-literal facade owner from source, and emits exactly one
fresh Count-v2 control object and one optimizing Count-v3 object for each
distinct pattern/semantic artifact row.

The authenticated selector universe is restricted before splitting or timing
by `minimum-haystack-4096-bytes-v1`: every selected cell has
`input_bytes >= 4096`. The build script independently enforces that floor.
Haystack length remains absent from the pattern-only compiler input.

The regex payload compiler receives no cell, job, family, partition, haystack,
oracle, or timing value. Cell attribution is joined only after all objects have
been compiled. Compiler self-hashes never become production authority.
Qualification calls only its private facade. Production adoption checks the
reviewed source tuple table and binds the real production facade before any
confirmation call.

## Build inputs

The build is fail-closed and accepts these environment variables:

- `FRE_COUNT_V3_BUILD_AUTHORITY`: exactly `qualification-private` or
  `production`. It must agree with exactly one same-named Cargo feature.
- `FRE_COUNT_V3_INVENTORY`: regular, non-symlink inventory JSON.
- `FRE_COUNT_V3_INVENTORY_SHA256`: independently frozen SHA-256 of those exact
  bytes.
- `FRE_COUNT_V3_ARTIFACT_ROOT`: existing absolute, non-symlink campaign
  directory. Objects and the registry are created write-once at
  content-addressed paths, fsynced, and made read-only; an existing path is
  accepted only when its exact bytes match.
- `FRE_COUNT_V3_TARGET_ID`: safe evidence target label.
- `FRE_COUNT_V3_TARGET_CONTRACT_SHA256`: frozen target/ABI/feature contract.
- `FRE_COUNT_V3_TUNING_CLASS`: `generic-aarch64`, `apple-m-series`, or
  `neoverse-v2-v3`.
- `FRE_COUNT_V3_REQUIRED_ISA`: `neon`, `sve-vl16`, or `sve2-vl16`. The selected
  optimizer/backend must independently emit that exact ISA row.

The SVE rows are mixed-register targets, not legacy pure-predicate targets:
`sve-vl16` requires register plan `4` and exact feature mask
`ASIMD|SVE`; `sve2-vl16` requires register plan `5` and exact feature mask
`ASIMD|SVE|SVE2`. Both require ELF64/AArch64 and exact VL16. The build,
embedded runner, production-proposal controller, and source-authority adopter
all reject legacy plans `2`/`3` and feature masks that omit ASIMD.
- `FRE_COUNT_V3_PROMOTION_PROPOSAL_SHA256` and
  `FRE_COUNT_V3_PROMOTION_MANIFEST_SHA256`: required only for a production
  build. They are the full-file digests (including the final LF) of the
  reviewed proposal and manifest. The manifest digest must also equal the
  nonzero manifest atom installed beside the exact source-authority tuple
  rows. Qualification builds refuse both variables.

A qualification build must use both
`FRE_COUNT_V3_BUILD_AUTHORITY=qualification-private` and
`--features qualification-private`. A production build must use both
`FRE_COUNT_V3_BUILD_AUTHORITY=production` and `--features production`. Missing,
mixed, or dual selectors are rejected.

Only `aarch64-apple-darwin` and `aarch64-unknown-linux-gnu` targets are
accepted. The former links Mach-O objects; the latter links ELF64/AArch64
objects. Count-v3 expectation, metadata, and payload symbols are
identity-suffixed. The expectation is placed in
`__FRE_CONST,__fre_expect` on Mach-O or the read-only allocated
`.rodata.fre.expect` input section on ELF. Linux links explicitly separate
code and read-only data load segments; the linked expectation must therefore
reside in an R-only, non-executable `PT_LOAD`.

The qualification build script writes
`fre.optimizing-count-v3.compiled-artifact-registry.v2` as
`compiled-artifacts.json` in `OUT_DIR`. It records
source, object, payload, metadata, expectation, optimizer-input, and
domain-separated provenance identities without any cell attribution.
Every `count-v3-aot` engine row also contains
`general_eligibility_tuple`, the exact 35-field
`CountGeneralEligibilityTupleV3` wire projection. Numeric fields retain their
wire integers, `little_endian` is a boolean, and `object_format` is its numeric
wire ID (`1` for Mach-O arm64 or `2` for ELF64 AArch64). The build derives this
projection from independently inspected object metadata and requires exact
equality with both `FocusedCompiledCountV3::general_eligibility_tuple()` and
the separately inspected static-expectation metadata. Control engine rows
carry `null`.

Production uses the distinct
`fre.optimizing-count-v3.production-confirmation-artifact-registry.v1`
schema. It adds the frozen cell join needed by the post-promotion controller,
marks qualification authority absent, and marks production authority as
requiring reviewed source tuples. It also embeds the proposal and manifest
digests plus the digest of the exact runtime source file that holds the
manifest atom and tuple rows. Both binaries embed their exact build authority
and a domain-separated hash binding it to the registry digest.

Eventual promotion does not enumerate Rebar cases, patterns, literals, or
artifact IDs. For each target, it joins evidence-passing eligible artifact IDs
to this authenticated registry, applies the separately qualified long-scan
routing floor, and deduplicates the complete tuple values into reviewed source
authority rows. Tuple equality alone does not enforce the haystack-length
floor.

Compile elapsed time and compiler peak RSS are process-level target-receipt
facts and must be captured by the external frozen build controller; they are
not nondeterministically embedded in this receipt.

## Linux post-link audit

Before running correctness or timing on Linux, verify the sealed runner against
its exact compiled registry:

```text
python3 -I -B verify_linux_expectations.py \
  --runner /absolute/fre-optimizing-count-v3-rebar \
  --registry /absolute/compiled-artifacts.json
```

The audit parses ELF64/AArch64 directly. For every registry expectation it
requires one hidden object definition of the exact width, authenticates the
linked bytes, requires an allocated non-W/non-X section in an exactly R-only
`PT_LOAD`, and rejects overlap with an executable load at the linker's maximum
page alignment.

## Qualification runtime protocol

In `qualification-private`, every invocation reads this exact compact UTF-8
request from stdin, with no trailing newline:

```json
{"process_nonce":"64-lower-hex","schema":"fre.optimizing-count-v3.runner-request.v1","target_id":"TARGET"}
```

The runner verifies canonical bytes and echoes their SHA-256 plus the nonce.
Commands are:

```text
fre-optimizing-count-v3-rebar inventory
fre-optimizing-count-v3-rebar correctness CELL_ID ENGINE 1
fre-optimizing-count-v3-rebar measure CELL_ID ENGINE ITERATIONS
```

`ENGINE` is one of `portable-current`, `count-v2-current`, or `count-v3-aot`.
Both `correctness` and `measure` emit exactly one
`fre.optimizing-count-v3.measurement-observation.v1` JSON object. It resolves
the cell and artifact, loads and authenticates the haystack, builds/adopts the
engine, rehashes the selected sealed engine artifact and the executable, and
verifies its oracle value before starting the timer. The timed loop contains
only the already-selected value call and checksum accumulation.
The correctness observation uses `iterations=1`, `searched_bytes=input_bytes`,
and `elapsed_ns=0`; it otherwise has the same exact 15 fields as a measurement
observation.

For `correctness` and `measure`, set `FRE_COUNT_V3_HAYSTACK_DIR` to a regular,
non-symlink content-addressed directory. Each haystack is a regular,
single-link file named exactly by its lowercase 64-hex inventory
`input_sha256`. The runner verifies its byte length and digest outside timing.

`inventory` emits the embedded pattern-only build receipt.
Qualification never grants production authority.

## Production confirmation protocol

The production binary uses distinct request, observation, and registry
schemas, all named
`fre.optimizing-count-v3.production-confirmation-*.v1`. It also provides
`authorize CELL_ID`. This command authenticates the selected object, obtains a
production handle through the source authority table, and binds the
fixed-policy FRE facade without executing native regex code. An unpromoted
tuple returns an error; it is never treated as portable permission.

For a retained Count-v3 timing, the runner:

1. source-authorizes and fully audits the linked object;
2. binds `AggregateCountExactLiteralAotV3` or
   `AggregateCountExactLiteralAotSveV3`;
3. requires the predicted route to be `AsimdAot` or `SveAot`;
4. executes one typed outcome call and requires the same native route; and
5. times only subsequent value-only facade calls.

Every production inventory cell is at least 4096 bytes. A shorter live input
is refused before timing even though the general production facade can
portably serve short inputs elsewhere. Production SVE/SVE2 session creation
requires the current Linux thread already to have exact VL=16 bytes; unlike
qualification, confirmation does not mutate the thread VL.

## Bounded post-promotion controller

`production_confirm.py` runs a resumable, fresh-process confirmation over an
explicit set of promoted cells. Its plan is exact compact sorted JSON with no
trailing newline:

```json
{"cells":[{"cell_id":"CELL","iterations":1000000}],"haystack_dir":"/absolute/content-addressed-haystacks","minimum_elapsed_ns":1000000000,"promotion":{"manifest_path":"/absolute/promotion-manifest.json","manifest_sha256":"64-lower-hex","proposal_path":"/absolute/promotion-proposal.json","proposal_sha256":"64-lower-hex"},"repetitions":30,"runner":{"path":"/absolute/sealed/fre-optimizing-count-v3-rebar","registry_sha256":"64-lower-hex","sha256":"64-lower-hex","timeout_seconds":120},"schema":"fre.optimizing-count-v3.production-confirmation-plan.v1","target_contract_sha256":"64-lower-hex","target_id":"TARGET","timing_wrapper":{"argv":["/absolute/sealed/wrapper","run-timing","--"],"contract":"full-lifetime-holder-no-child-on-exit-75-v1","executable_sha256":"64-lower-hex"}}
```

Run or resume it with:

```text
python3 production_confirm.py PLAN.json /absolute/JOURNAL.jsonl /absolute/SUMMARY.json
```

The wrapper `argv` is an opaque caller-supplied prefix. The controller
authenticates its absolute read-only executable and launches every correctness
and measurement process as:

```text
WRAPPER_PREFIX RUNNER (correctness|measure) CELL ENGINE ITERATIONS
```

Thus the admission holder covers the runner's full lifetime; there is no
probe/release race. The declared wrapper contract requires exit 75 to mean
that no runner child was started. The controller accepts 75 only with empty
stdout, fsyncs the denial, and immediately returns 75 without waiting or
retrying. It never retains or replaces a sample from a denied launch. A later
invocation resumes the exact journal prefix. The controller never searches
`PATH`, waits for an idle host, or signals unrelated work. A timeout kills only
the new process group containing its own wrapper and runner.

Before scheduling anything, the controller authenticates the exact
LF-terminated promotion proposal and manifest from the plan. It closes the
manifest projection and global qualified-tuple set over the proposal, selects
the exact target, checks the production registry/binary promotion hashes, and
requires every selected cell's complete 35-field tuple to byte-match a
qualified class for that target. The registry must expose one current portable
control, one current Count-v2 control, and one real production Count-v3 row per
compiled pattern; controls cannot carry a production tuple.

All selected cells are authorized in fresh processes before any correctness or
timing process starts. Any unpromoted tuple or other authorization failure is
sealed as terminal. The retained schedule then runs all three engines in all
six rotating orders, requires at least 30 repetitions in complete six-order
blocks, and requires every sample to last at least one second.

The create-only sealed summary contains every paired elapsed value and reports:

- per-cell and per-source-tuple Count-v3/portable and
  Count-v3/faster-current-control geometric-mean ratios;
- the exact integer-product test
  `Count-v3/faster-current-control < 4/5`;
- at least `ceil(4 * repetitions / 5)` strict paired wins per cell; and
- the same exact ratio and at-least-80%-wins gates per tuple and for the target
  aggregate across all retained cells; and
- exact balanced coverage of all six engine orders.

The summary status is `pass` only when every cell, every source tuple, the
target aggregate, and the six-order balance pass those gates. It reports the
selected cell IDs and binds the qualification ID/spec, qualification artifact
registry, proposal, manifest, production-authority source, payload, plan,
journal, production registry, source set, runner, and timing wrapper. This
confirmation is downstream of promotion; it does not replace held-out
qualification evidence or create source authority.
