# External static Search runner

This runner compiles four independently sourced exact literals into native
AArch64 object files, publishes receipt-bound private family glue, links the
objects into one executable, adopts them through the real static runtime, and
binds the public automatic portable-prefix/AOT-tail facade. It never invokes
LLVM or JIT publication.

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
written to a copy of `static-runner-identity-template-v1.json`, an explicitly
unsealed artifact-only build is:

```sh
FRE_EXTERNAL_SEARCH_STATIC_IDENTITY=/absolute/path/static-runner-identity.json \
FRE_EXTERNAL_SEARCH_RUNNER_REVISION=0123456789abcdef0123456789abcdef01234567 \
FRE_EXTERNAL_SEARCH_ALLOW_UNSEALED_ARTIFACT_BUILD=1 \
CARGO_TARGET_DIR=/absolute/path/fre-external-static-target \
cargo build --release --locked \
  --manifest-path research/aot/external-regex-1.12.4/static-runner/Cargo.toml
```

`build.rs` emits and passes eight exact object paths to the final link: one
implementation object and one receipt-bound family-glue object for each
literal. Mach-O links with immutable text/constant segment protections and
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
  run /private/tmp/fre-external-regex-dev-fixtures-v2 > /absolute/path/results.csv

python3 research/aot/external-regex-1.12.4/static-runner/analyze.py \
  /absolute/path/results.csv
```

Each engine sample is at least 400 ms, engine order alternates, both engines
use the same calibrated iterations, and checksums and semantics must agree.
Tail ownership is derived from the frozen window floor and portable-prefix
policy, not from fixture scenario names.
