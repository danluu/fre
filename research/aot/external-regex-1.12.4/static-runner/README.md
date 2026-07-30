# External static Search runner

This runner compiles an authenticated manifest of independently sourced exact
literals into native AArch64 object files, publishes receipt-bound private
family glue, links the objects into one executable, adopts them through the
real static runtime, and binds the public automatic portable-prefix/AOT-tail
facade. It never invokes LLVM or JIT publication.

The immutable development corpus contains 28 one-MiB fixtures: four literals
from upstream `regex` 1.12.4, each with `absent`, `early`, `middle`, `tail`,
`dense`, `wrong-final-dense`, and `wrong-first-dense` scenarios. Rebar is not a
qualification input.

## Selector-neutral check

From the repository root:

```sh
cargo check --locked \
  --manifest-path research/aot/external-regex-1.12.4/static-runner/Cargo.toml
```

The build warning reports the authenticated runner source-set SHA-256. With no
identity environment variable, the runner remains selector-neutral and emits
or links no candidate object.

## Object generation and exact link

After a reviewed backend tag, family selector, routing identities, window
floor, portable-prefix width, and per-platform manifest identity have been
written to a copy of `static-runner-identity-template-v2.json`, an explicitly
unsealed artifact-only build is:

```sh
FRE_EXTERNAL_SEARCH_STATIC_IDENTITY=/absolute/path/static-runner-identity.json \
FRE_EXTERNAL_SEARCH_OBJECT_CANDIDATE_MANIFEST=/absolute/path/candidate-manifest.json \
FRE_EXTERNAL_SEARCH_RUNNER_REVISION=0123456789abcdef0123456789abcdef01234567 \
FRE_EXTERNAL_SEARCH_ALLOW_UNSEALED_ARTIFACT_BUILD=1 \
CARGO_TARGET_DIR=/absolute/path/fre-external-static-target \
cargo build --release --locked \
  --manifest-path research/aot/external-regex-1.12.4/static-runner/Cargo.toml
```

The v2 identity authenticates the candidate manifest's schema, exact file
SHA-256, and cardinality. The manifest must expose
`payload.candidate_count` and `payload.candidates`; each candidate supplies a
unique semantic SHA-256, literal hex, width, and literal SHA-256. The build
derives a canonical byte-exact regex source from each literal, reauthenticates
the exact-literal plan, and refuses empty, duplicate, out-of-envelope, or
unbounded manifests. This accepts the frozen four-candidate development
fixture manifest and successor width-stratified fixture manifests without a
source-code cardinality change. The v1 identity remains accepted only with its
already authenticated four-candidate fixture manifest and retains its prior
raw-UTF-8/Unicode source construction. The source-construction mode is emitted
into the build receipt and generated bindings.

Application fixture manifests retain their frozen
`required-tag29-frozen-input` backend provenance label, but that label has no
backend-selection authority. At runtime the exact v2 application fixture
manifest is admissible only when the separately generated, linked controller
bindings prove the exact five-object application manifest, backend tag 29 /
`AsimdV16`, the frozen 4,093-byte window and 256-start portable prefix, a
nonzero private family selector, and nonzero whole-identity, runner-source,
plan, analyzer, and evidence SHA-256 identities. A wrong or unresolved backend
with the same fixture label is refused. `required-unresolved-input` remains
backend-neutral fixture provenance; neither provenance value can grant timing.

`build.rs` emits and passes two exact object paths per manifest candidate to
the final link: one implementation object and one receipt-bound family-glue
object. Mach-O links with immutable text/constant segment protections and
reproducible output; ELF links with a non-executable stack and no build ID.
Both links write a map and a content-addressed build receipt under `OUT_DIR`.

Unsealed builds cannot time. For timing, first require a complete frozen
identity:

```sh
python3 research/aot/external-regex-1.12.4/validate_static_runner_identity.py \
  require-development-timing /absolute/path/static-runner-identity.json
```

Then run the same release build without
`FRE_EXTERNAL_SEARCH_ALLOW_UNSEALED_ARTIFACT_BUILD`. The runner revision must
be the full commit recorded in the identity, and the source-set SHA-256 must
match the warning from the selector-neutral check.

## Correctness and timing

```sh
/absolute/path/fre-external-static-target/release/fre-external-regex-static-runner \
  inspect /private/tmp/fre-external-regex-dev-fixtures-v2

/absolute/path/fre-external-static-target/release/fre-external-regex-static-runner \
  run /private/tmp/fre-external-regex-dev-fixtures-v2 0 1 \
  > /absolute/path/results.csv

python3 research/aot/external-regex-1.12.4/static-runner/analyze.py \
  /absolute/path/results.csv
```

Each engine sample is at least 400 ms, engine order alternates, both engines
use the same calibrated iterations, and checksums and semantics must agree.
For the broad evidence manifests, tail ownership is derived from the frozen
source-only eligibility projection and the preregistered prefix-owned
`early`/`dense` scenarios. The result adapter independently recomputes it.

The final two arguments are a zero-based shard index and a positive shard
count. Fixtures are assigned by canonical manifest ordinal modulo shard
count. Every independently launched shard emits its own header; evidence
adapters must authenticate, deduplicate, and join the complete shard set.
