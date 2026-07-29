# Optimizing Count-v3 compiled-Rebar runner

This is the qualification-private, fresh-process runner for the source-only
Count-v3 AOT campaign. It is intentionally a standalone Cargo workspace. Its
build script authenticates one frozen Rebar inventory, reconstructs every
fixed-policy exact-literal facade owner from source, and emits exactly one
fresh Count-v2 control object and one optimizing Count-v3 object for each
distinct pattern/semantic artifact row.

The authenticated selector universe is restricted before splitting or timing
by `minimum-haystack-4096-bytes-v1`: every selected cell has
`input_bytes >= 4096`. The build script independently enforces that floor.
Haystack length remains absent from the pattern-only compiler input.

The regex payload compiler receives no cell, job, family, partition, haystack,
oracle, or timing value. Cell attribution is joined only after all objects have
been compiled. Count-v3 is called only through the qualification-private static
adopter and the facade-bound value API; compiler self-hashes never become
production authority.

## Build inputs

The build is fail-closed and accepts these environment variables:

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

Only `aarch64-apple-darwin` and `aarch64-unknown-linux-gnu` targets are
accepted. The former links Mach-O objects; the latter links ELF64/AArch64
objects. Count-v3 expectation, metadata, and payload symbols are
identity-suffixed. The expectation is placed in
`__FRE_CONST,__fre_expect` on Mach-O or the read-only allocated
`.fre.expect` section on ELF.

The build script writes
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

Eventual promotion does not enumerate Rebar cases, patterns, literals, or
artifact IDs. For each target, it joins evidence-passing eligible artifact IDs
to this authenticated registry, applies the separately qualified long-scan
routing floor, and deduplicates the complete tuple values into reviewed source
authority rows. Tuple equality alone does not enforce the haystack-length
floor.

Compile elapsed time and compiler peak RSS are process-level target-receipt
facts and must be captured by the external frozen build controller; they are
not nondeterministically embedded in this receipt.

## Runtime protocol

Every invocation reads this exact compact UTF-8 request from stdin, with no
trailing newline:

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
Neither mode grants production authority.
