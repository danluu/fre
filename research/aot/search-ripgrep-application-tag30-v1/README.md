# Tag-30 ripgrep application qualification

This directory is the result-blind, non-Rebar application gate for the
tag-30 `AsimdV17` Search family. It reuses the already-frozen v2 ripgrep
source projection and all 154 one-megabyte fixtures without changing,
excluding, or reweighting any member. It does not read or materialize the
external-regex heldout.

The source set contains eleven exact literals. The unchanged phase-unique
selector admits five (`Watson`, `NO MATCH`, `Sherlock`, `DOES NOT MATCH`, and
`Doctor Watsons`) and structurally refuses six. The separate application link
manifests compile exactly those five literals with backend tag 30,
`SEARCH_V17`, candidate policy 15, and no LLVM. The linked runner adopts the
objects through private family selector 13; it never grants production
authority.

## Frozen routes and gates

Every fixture runs on both the Apple AArch64 host and the C9g AArch64 host.
Correctness, all eleven compiler dispositions, physical alignment, and the
exact route proof are consumed before the analyzer opens timing:

- 75 eligible fixtures miss the authoritative 256-candidate-start portable
  prefix and invoke the disjoint tag-30 static tail. Every fixture median must
  be strictly less than `0.80` on each host.
- 10 eligible `early`/`dense` fixtures return from the portable prefix without
  invoking the static tail. Every fixture median must be at most `1.05`.
- 69 structurally ineligible fixtures use the full portable fallback. Every
  fixture median must be at most `1.05`.

A fixture median sorts six alternating-order exact rational
`candidate_elapsed_ns / portable_elapsed_ns` ratios and averages the middle
two without pre-rounding. Each variant ramps to a 50 ms calibration floor,
retains three same-iteration anchors, and the pair uses the largest
target-rate projection across all six anchors. Each timed variant
independently runs for at least 400 ms with the same iteration count and
output checksum under its authenticated CPU-residence contract. There is no
aggregate rescue and no result-derived exclusion.

`projection-v1.jsonl` is a byte-exact derivation of the old source and fixture
freeze. Its 154 rows and route cardinalities are independently reconstructed
by `prepare_projection.py`. The runner authenticates the entire projection
before selecting one of sixteen deterministic ordinal shards.

## Fail-closed binding sequence

`qualification-identity-template-v1.json` binds the final tag-30 campaign
plan, analyzer source, pre-result campaign-intent evidence, and reviewed
private-family authorization identities. It deliberately remains unsealed:
the application runner revision/source archive, compiler identity, platform
manifest identities, and sealed build receipts are unresolved.
`campaign-binding-template-v1.json` carries the same fail-closed state for
analysis and pre-registers Apple Super-cluster worker labels 12–17 and
disjoint C9g CPUs 64–79. On the authenticated M5 Max, Mach affinity status
zero or `KERN_NOT_SUPPORTED` is accepted only after the exact machine and
performance-level topology is authenticated. Every measured variant records
a five-second bounded wall-time Super-class wait followed by bounded CPU-only
retries, and is accepted only when both sampled endpoints are in the Super
class. Linux retains exact requested-CPU residence.

The two pending campaign values are deliberately distinct. The private-family
authorization identity is the raw discovery-authorization file SHA-256. The
campaign evidence identity is
`SHA256(intent-domain || raw campaign-contract digest || raw campaign-analyzer
digest || raw discovery-authorization-file digest)`.

The required sequence is:

1. Merge this application runner on top of the final tag-30 campaign and
   renderer commits.
2. Fill the application identity with the exact application runner revision,
   source-archive identity, compiler-source identity derived from both, and
   the exact installed private-family source identity.
3. Perform application object-only discovery on both targets, bind both
   emitted manifest identities, and rebuild from one exact source archive.
4. Set `bindings_complete`,
   `application_qualification_authority`, and
   `development_timing_permitted` only in the sealed identity; leave
   `production_authority=false`.
5. Run all correctness shards on both hosts, then all timing shards, and
   analyze the exact 64-fragment result directory.

Supplying the checked-in unresolved identity to a linked build fails before
object emission or timing. Selector-neutral `cargo check` and unit tests remain
available without an identity.

## Reproduction

Validate the immutable source and link derivations:

```sh
python3 research/aot/search-ripgrep-application-tag30-v1/validate_link_manifests.py .

python3 research/aot/search-ripgrep-application-tag30-v1/prepare_projection.py \
  . /path/to/frozen-fixtures /new/projection.jsonl
cmp /new/projection.jsonl \
  research/aot/search-ripgrep-application-tag30-v1/projection-v1.jsonl
```

Build and test the selector-neutral runner:

```sh
cargo check \
  --manifest-path research/aot/search-ripgrep-application-tag30-v1/Cargo.toml
cargo test \
  --manifest-path research/aot/search-ripgrep-application-tag30-v1/Cargo.toml
```

Run the full synthetic contract and adversarial suite:

```sh
python3 research/aot/search-ripgrep-application-tag30-v1/test_qualification_results.py \
  . /path/to/exact/ripgrep-checkout /path/to/frozen-fixtures
```

Analyze sealed results:

```sh
python3 research/aot/search-ripgrep-application-tag30-v1/analyze_qualification_results.py \
  . /path/to/exact/ripgrep-checkout /path/to/frozen-fixtures \
  /sealed/campaign-binding.json EXPECTED_BINDING_FILE_SHA256 \
  /sealed/exact-64-fragment-result-directory
```

`run_shards.py` runs one host/mode phase with one serialized queue per frozen
CPU. It publishes only complete read-only fragments into the result directory;
attempt logs and partial files stay in a separate control directory. Repeating
an interrupted phase validates and skips completed fragments, so a client or
rate-limit interruption does not discard finished work.
