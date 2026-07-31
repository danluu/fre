# Search tag-29 topology generalization freeze

This campaign qualifies byte-topology behavior that a one-literal-per-width
screen cannot cover. It is completely synthetic and result blind: neither the
generator nor the frozen projection reads a corpus, benchmark result, network
resource, or Rebar artifact.

The full projection contains exactly 123,424 procedural fixtures:

```text
29 widths (4..32)
× 7 literal topology classes
× 19 learned-mismatch classes
× 32 geometries (16 logical prefixes × short/long)
```

All rows are correctness and routing gates on both AArch64 hosts. The matrix
includes width and periodicity refusals, short-window portable routing,
guard-page boundaries, absent searches, tail matches, all five literal phase
classes, all five actual primary-selector offset classes modulo five, and
learned bytes that are absent, selected-primary, selected-secondary, terminal,
or modal literal bytes.

Every eligible long/native row mutates only an unselected literal offset and
the generator asserts that all five selected columns remain equal. These rows
therefore survive the initial filter, reach an exact false candidate, and
exercise mismatch-directed learning. Selected/general mutations remain in the
short portable correctness stratum and in the separate exhaustive
one-literal-per-width campaign; they cannot masquerade as learned timing.

Long timing is intentionally not the full Cartesian product. Before any
result exists, `freeze-v1.json` selects one long geometry for each eligible
width/topology/mutation cell: 3,078 fixtures. This retains every width 6..32,
six eligible topology classes, all 19 mismatch classes, all five selector
primary-offset classes, all five independently named literal phase classes,
all 16 logical prefixes, and window sizes from 4,093 bytes through 1 MiB.
Every individual cell must beat portable by more than 20% on each host. One
failing cell rejects the broad family; a result cannot create a new exclusion.

Logical prefix length is not claimed to be physical address alignment. For a
right-padded mapping, the runner places the checked-window start at the
recorded mod-16 address. For a right-guarded mapping, it places the
checked-window end at a page boundary, making start alignment exactly
`(-window_bytes) mod 16`. The freeze records exact counts for both mapping
classes and every realized physical alignment.

The exact source-kind, source-relation, topology/relation, literal-phase,
selector-primary, logical-prefix, physical-alignment, guard-mapping, window,
width, and topology distributions are part of the checked-in freeze.
Topology-intrinsic gaps are explicit rather than silently filled: for
example, a high-entropy-distinct literal has no repeated source relation, and
some low-entropy rows must use the recorded absent-byte fallback.

The fixture recipe uses a byte absent from the literal as both separator and
guard. It tiles a one-byte near miss followed by that separator, optionally
installs one true literal at the last candidate start, and requires a scalar
oracle before either measured engine executes. Materializing rows on demand
keeps the checked-in freeze compact without weakening its projection hash.

Rebar is not read, classified, or used for membership, thresholds, or
promotion. It may only be run after the promotion decision is frozen, as
non-authorizing corroboration.

Recompute the frozen identities without materializing JSONL:

```sh
python3 research/aot/search-tag29-topology-generalization-v1/validate_freeze.py
```

## Fail-closed result contract

`analyze_qualification_results.py` uses the v2 result contract. Its invocation
is:

```text
analyze_qualification_results.py QUALIFICATION_DIR \
  CAMPAIGN_AUTHORITY EXPECTED_AUTHORITY_FILE_SHA256 RESULT_MANIFEST
```

`CAMPAIGN_AUTHORITY` must have the exact flat name
`campaign-authority.json`. The controller supplies its whole-file SHA-256
separately, before any result exists. The result manifest does not contain an
authority object; it contains only the exact authority-file SHA-256 and the
campaign identity derived from that SHA-256. Consequently, rehashing a
result-supplied authority cannot authorize a campaign.

The authority pins the analyzer and qualification validator sources, runner,
controller, sealer, source set, plan, backend, ordinary and baseline entries,
single timed-function identity, exact host attestations and build/link
identities, and a nonempty sorted set of allowed logical CPUs for each host.
It also pins one exact flat compiler/link evidence file per host:

```text
apple-aarch64-asimd.compiler-object-link-evidence.json
c9g-aarch64-asimd-sve2.compiler-object-link-evidence.json
```

The evidence is an envelope with schema
`fre.aot.search-tag29-compiler-object-link-evidence.v1`, a canonical payload
hash, and a payload. The payload binds the exact frozen/canonical host,
target triple and feature object; both qualification object/disposition
manifests; external verifier, build, link, map and final-image identities;
and the authority-pinned linked image.

The accepted link-proof verifier source SHA-256 is
`5e7e347f8796941fb7dfa654ad011400c20461d53784837d53a793e7756db38d`;
its contract SHA-256 is
`42921564050b795b4a097c8b74dde2e947b914931e71dd5faafe274a4975e60e`.

Its `objects` array is an exact ordered bijection with all 808 object
candidates. Each entry contains:

```text
ordinal
literal_sha256
semantic_candidate_sha256
compile_identity
compile_receipt_sha256
implementation_object_sha256
glue_object_sha256
implementation_symbols {entry, payload, metadata}
glue_symbol
glue_symbol_identity_sha256
glue_relocation_targets [entry, payload, metadata]
implementation_linker_input_multiplicity
glue_linker_input_multiplicity
link_map_origins
final_image_retentions
```

Both multiplicities must be the strict integer `1`. Every implementation
symbol and the glue symbol must suffix-match the full nonzero 64-hex compile
identity. Compile identities, compile receipts, implementation objects, glue
objects, and symbols are injective. Origin and retention arrays are exact
ordered records `{symbol, object_sha256, receipt_sha256}` for entry, payload,
metadata, then glue. Their symbol/object pairs must match their enclosing
objects and every proof receipt is injective. `refusals` is the exact ordered
114-literal structural-refusal bijection with a unique compile receipt.

The result directory has exact flat bundle names. Each host supplies one
`*.correctness.jsonl` with all 123,424 frozen rows and one `*.timing.jsonl`
with all 3,078 preselected cells. Both correctness bundles are fully consumed
and authenticated before either timing bundle is read. The correctness pass
checks scalar, forced-portable and candidate spans and counts; exact compiler
disposition and external object proof; exact route/static invocation; and
physical padding/guard receipts for every row.

All input files are opened relative to held directory descriptors with
`O_NOFOLLOW`. The analyzer hashes and parses the same held descriptor,
rejects links and metadata changes, and permits only exact flat names. Result
integer fields reject booleans, mappings require nonzero bounded allocation
ranges, receipt identities are unique and case-bound, CPUs must belong to the
pre-authorized host set, and one semantic accumulator must remain constant
across all six order-paired measurements.

Run the full synthetic v2 contract and adversarial mutation test with:

```sh
python3 research/aot/search-tag29-topology-generalization-v1/test_qualification_tools.py \
  QUALIFICATION_DIR
```
