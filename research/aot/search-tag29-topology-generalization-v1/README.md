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
× 32 geometries (16 alignments × short/long)
```

All rows are correctness and routing gates on both AArch64 hosts. The matrix
includes width and periodicity refusals, short-window portable routing,
guard-page boundaries, absent searches, tail matches, every selector phase,
and learned bytes that are absent, selected-primary, selected-secondary,
terminal, or modal literal bytes.

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
phase placements, all 16 alignments, and window sizes from 4,093 bytes through
1 MiB. Every individual cell must beat portable by more than 20% on each host.
One failing cell rejects the broad family; a result cannot create a new
exclusion.

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
