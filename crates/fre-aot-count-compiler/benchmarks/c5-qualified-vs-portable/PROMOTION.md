# C5 production promotion

This transaction promotes one already measured C5 Count-v2 row. It is not a
claim that FRE has a full regex AOT compiler.

## Exact scope

| Dimension | In this C5 Candidate | Outside this Candidate |
| --- | --- | --- |
| Operation | Whole-haystack, non-overlapping `Count-v2` | Generic search, find, captures, replace, split, or arbitrary aggregate operators |
| Pattern | One exact byte literal, `needle`, selector 11 | Alternation, repetition, classes, Unicode semantics, or general regex plans |
| Native backend | FRE's direct AArch64 exact-count emitter | x86-64 and other instruction sets |
| Published object | arm64 Mach-O implementation and final-image glue objects | ELF, COFF, dynamic loading, or a portable artifact container |
| Qualified host | arm64 macOS, with immutable `__FRE_CONST` final-image ranges | Linux, Windows, iOS, and cross-host deployment |
| Runtime route | Static link, exact literal row, mapped-image verification, authenticated process-static handle | Runtime code generation, general AOT artifact discovery, cache/distribution, or arbitrary-row registration |
| Compiler dependency | No LLVM/Inkwell/Cranelift dependency in the focused Count compiler | `rustc` may use LLVM and Apple clang/ld performs final linking; neither compiles the Count program |
| Performance evidence | Cache-resident steady-state safe-handle calls and separately labeled qualification-private first/cached adoption | Compile/object generation, final link, process startup, production-adoption latency, or end-to-end lifecycle advantage |

The receipt framing and candidate-extracted verification pattern can be reused
for later row types, but this verifier deliberately renders only
`C5_PROMOTION_BUNDLE_MANIFEST_SHA256_V2` in
`crates/fre-aot-static-runtime/src/support.rs`. Search or aggregate AOT rows
must have their own measured envelope, identities, runtime contract, and
promotion atom.

The matrix has 58 exact cases and binds 174 process/case median gates plus 2,784
paired repetitions. Its binary, natural-text, alignment, selected-filter, and
run-transition diversity strengthens evidence for this one `needle` artifact;
it does not generalize authorization to another literal, selector, backend, or
regex shape.

## Independent review receipt

The review receipt must be a regular, single-link file outside the resealable
bundle. Its complete SHA-256 is supplied independently to the verifier. It has
exactly these twenty-two TSV rows:

```text
schema	fre-aot-count-c5-independent-review-v3
candidate_commit	CANDIDATE
candidate_tree	CANDIDATE_TREE
benchmark_source_sha256	BENCHMARK_SOURCE_SHA256
benchmark_binary_sha256	BENCHMARK_BINARY_SHA256
cargo_binary_sha256	CARGO_BINARY_SHA256
rustc_binary_sha256	RUSTC_BINARY_SHA256
rustdoc_binary_sha256	RUSTDOC_BINARY_SHA256
toolchain_closure_sha256	TOOLCHAIN_CLOSURE_SHA256
toolchain_closure_entries	TOOLCHAIN_CLOSURE_ENTRIES
toolchain_closure_bytes	TOOLCHAIN_CLOSURE_BYTES
cargo_registry_closure_sha256	CARGO_REGISTRY_CLOSURE_SHA256
cargo_registry_closure_entries	CARGO_REGISTRY_CLOSURE_ENTRIES
cargo_registry_closure_bytes	CARGO_REGISTRY_CLOSURE_BYTES
resource_coordinator_sha256	RESOURCE_COORDINATOR_SHA256
resource_coordinator_cutover_receipt_sha256	CUTOVER_RECEIPT_SHA256
bundle_manifest_sha256	BUNDLE_MANIFEST_SHA256
evidence_class	measured
verifier_commit	CANDIDATE
dependency_rederive_sha256	DEPENDENCY_TREE_SHA256
review_evidence_sha256	NONZERO_INDEPENDENT_EVIDENCE_SHA256
overall	PASS
```

`dependency_rederive_sha256` is the SHA-256 of the normalized
`dependency-tree.txt` obtained by independently rerunning the Candidate's five
locked/offline `cargo tree` queries in a controlled review environment. It
must byte-match the report snapshotted and checked by the Candidate verifier.
That environment must use the externally pinned Cargo/rustc/rustdoc,
toolchain-closure, and Cargo-registry-closure identities recorded above. The
reviewer also independently pins the exact coordinator and unparsed cutover
receipt bytes; no unknown receipt field is inferred before the post-GO
interface is published. This makes the reviewer attest a dependency
rederivation and admission provenance pinned to the exact Candidate, source
identity, and bundle manifest rather than merely accepting a producer-written
receipt.

The AOT verifier's direct trust closure is the exact Candidate blobs and modes
for:

- `verify-promotion-delta.sh` (`100755`);
- `qualification-common.sh` (`100644`), including the canonical atom renderer;
- `verify-qualification-bundle.sh` (`100755`).

The v2 benchmark source manifest is an exact, strictly sorted 21-file closure.
It includes all three trust-closure files, the trust-root regression, the
source-identity manifest itself, externally runnable toolchain and Cargo
registry fingerprint commands, the coordinator-only timing-wave helper, and
the correctness-only promoted-source harness. The regression caps its own
Candidate blob before comparison, but it is a test of the gate rather than a
production trust root; the production decision is made only by the three-file
verifier closure above.

The bundle verifier additionally requires `source.tar` to be byte-identical to
`git archive` of the Candidate and executes the archived, receipt-pinned
`verify-results.sh`. It canonically parses both the archived workspace and
standalone-benchmark Cargo v4 lockfiles and rejects package names in the
LLVM/Inkwell/Cranelift compiler families. It also requires the archived
static-runtime and benchmark feature sections, the benchmark dependency
section, and the workspace-wide private-feature manifest inventory to match
the closed qualification/private-separation contract exactly. The recorded
dependency tree remains bounded corroborating evidence; the promotion command
does not invoke Cargo, Rustup, or an ambient compiler toolchain.

No verifier supplied only by the bundle or promoted commit is accepted as
authority. Candidate blob extraction, changed-path output, dependency report,
and review snapshot sizes are bounded before use.
Producer-local toolchain and registry paths remain in fingerprint/build
receipts as audit provenance. Promotion intentionally cross-binds their
digest/count/byte identities, not equal absolute paths across reviewer hosts.

## Verify the delta

For an AOT-only promotion, the promoted commit must be a direct child of the
Candidate and `support.rs` must be its only changed path:

```console
./verify-promotion-delta.sh \
  REPOSITORY CANDIDATE PROMOTED CANDIDATE_TREE \
  BENCHMARK_SOURCE_SHA256 BENCHMARK_BINARY_SHA256 \
  BUNDLE_MANIFEST_SHA256 \
  CARGO_BINARY_SHA256 RUSTC_BINARY_SHA256 RUSTDOC_BINARY_SHA256 \
  TOOLCHAIN_CLOSURE_SHA256 TOOLCHAIN_CLOSURE_ENTRIES \
  TOOLCHAIN_CLOSURE_BYTES \
  CARGO_REGISTRY_CLOSURE_SHA256 CARGO_REGISTRY_CLOSURE_ENTRIES \
  CARGO_REGISTRY_CLOSURE_BYTES \
  RESOURCE_COORDINATOR_SHA256 CUTOVER_RECEIPT_SHA256 BUNDLE_DIR \
  INDEPENDENT_REVIEW.tsv INDEPENDENT_REVIEW_SHA256
```

When a Candidate-rooted top-level verifier owns an exact multi-domain union,
it may call the AOT verifier with one final argument:

```text
composed-exact-union-delegated
```

That mode still requires one direct child, exact external identities, the exact
C5 atom rendering, the independent review pin, and Candidate-extracted bundle
replay. It delegates only the global changed-path union to the combined
verifier.

For an AOT-only promotion, run the positive-plus-adversarial gate:

```console
./test-promotion-trust-root.sh \
  REPOSITORY CANDIDATE PROMOTED CANDIDATE_TREE \
  BENCHMARK_SOURCE_SHA256 BENCHMARK_BINARY_SHA256 \
  BUNDLE_MANIFEST_SHA256 \
  CARGO_BINARY_SHA256 RUSTC_BINARY_SHA256 RUSTDOC_BINARY_SHA256 \
  TOOLCHAIN_CLOSURE_SHA256 TOOLCHAIN_CLOSURE_ENTRIES \
  TOOLCHAIN_CLOSURE_BYTES \
  CARGO_REGISTRY_CLOSURE_SHA256 CARGO_REGISTRY_CLOSURE_ENTRIES \
  CARGO_REGISTRY_CLOSURE_BYTES \
  RESOURCE_COORDINATOR_SHA256 CUTOVER_RECEIPT_SHA256 BUNDLE_DIR \
  INDEPENDENT_REVIEW.tsv INDEPENDENT_REVIEW_SHA256
```

It rejects extra and indirect deltas, an oversized Candidate trust blob, a
self-approved resealed bundle, a same-tree stale Candidate, synthetic or
mismatched review receipts, an oversized or inside-bundle review, and
mismatched dependency rederivations or
tree/source/binary/manifest/toolchain inputs.

## Post-GO atom-only production correctness replay

This is a correctness gate after promotion, not a new timing subject. Run it
only after build admission is open. Preserve separate clean Candidate and
Promoted checkouts; the latter must be the verified atom-only direct child.

First generate the same C5 implementation with production, rather than private
qualification, final-image glue. Omit `--qualification-private`:

```console
cargo run \
  --manifest-path CANDIDATE/Cargo.toml \
  -p fre-aot-count-compiler \
  --example emit_c3_evidence \
  --release --locked --offline -- \
  /private/tmp/fre-aot-c5-production-objects
```

For both checkouts, run `fre-aot-static-runtime` tests under all four modes:

```text
--no-default-features
--no-default-features --features linked-count-v2
--no-default-features --features linked-hardware-matrix-v2
--all-features
```

The Candidate must retain an empty production table. The Promoted checkout
must expose selector 11 and reject every other selector. The all-features test
`production_and_qualification_registries_have_distinct_storage` plus the
foreign-registry handle test must pass in both checkouts.

Then build and run the correctness-only binary from each checkout in these
four feature-unification modes:

| Package mode | Candidate argument and result | Promoted argument and result |
| --- | --- | --- |
| `promotion-correctness` | `candidate` -> `candidate-no-qualified-row` | `promoted-unavailable` -> `promoted-verification-refused` |
| `promotion-correctness,production-linked-count` | `candidate` -> `candidate-no-qualified-row` | `promoted` -> `promoted-qualified-row` |
| `promotion-correctness,production-hardware-matrix` | `candidate` -> `candidate-no-qualified-row` | `promoted` -> `promoted-qualified-row` |
| `promotion-correctness,production-all-runtime` | `candidate` -> `candidate-no-qualified-row` | `promoted` -> `promoted-qualified-row` |

The first Promoted row proves fail-closed behavior when the source atom names
selector 11 but mapped-image verification is not compiled in. It must return
the coarse safe-adapter `VerificationRefused` status before any linked pointer
is read. The other three Promoted rows exercise successful production
adoption with linked Count-v2 enabled. The correctness binary rejects
`promoted-unavailable` in a linked mode and rejects `promoted` in the
feature-disabled mode, so the expected state cannot be selected loosely.

For each mode:

```console
FRE_C5_PRODUCTION_OBJECT_DIR=/private/tmp/fre-aot-c5-production-objects \
CARGO_TARGET_DIR=CHECKOUT_SPECIFIC_TARGET \
cargo build \
  --manifest-path CHECKOUT/crates/fre-aot-count-compiler/benchmarks/c5-qualified-vs-portable/Cargo.toml \
  --bin fre-aot-count-promoted-correctness \
  --no-default-features --features PACKAGE_MODE \
  --release --locked --offline

CHECKOUT_SPECIFIC_TARGET/release/fre-aot-count-promoted-correctness \
  candidate-or-promoted-unavailable-or-promoted
```

All four Candidate executions must report
`state=candidate-no-qualified-row`. The feature-disabled Promoted execution
must report `state=promoted-verification-refused`. The three linked Promoted
executions must report `state=promoted-qualified-row` after the ordinary safe
adapter adopts selector 11 and the linked handle returns exact counts for
absent, singleton, separated, and adjacent literals. The private qualification
adapter is never used by this correctness binary.
