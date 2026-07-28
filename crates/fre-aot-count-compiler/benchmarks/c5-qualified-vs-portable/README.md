# Qualified Count-v2 AOT versus portable

This standalone package links the exact C5 candidate implementation and
final-image glue into the benchmark executable. It retrieves the entry only
through `fre-aot-static-runtime`'s explicitly unsafe, separately named
qualification adopter, immutable Mach VM checks, identity checks, payload hash,
and isolated qualification registry. The safe production adopter always uses
only the production row table, even when Cargo unifies all features. Ordinary
`linked-count-v2` builds keep that table empty until a separately reviewed
bundle-manifest promotion atom is pinned in source.

The custom-emitted final-image receipt pins the glue adopter as
`qualification-private`; the sealed build also retains a bounded symbol-gate
report proving that adopter is absent from ordinary production feature
combinations.

The steady-state AOT rows call `VerifiedStaticCountV2::count`, including the
same per-call policy preflight used by production. Initial adoption and cached
adoption are reported separately. The portable comparison uses the current
exact-literal `AggregateCountRegex::count_value` route.

The sealed matrix contains 58 cases: 29 at 64 KiB and the same 29 at 1 MiB.
Each size covers sparse present, easy absent, dense matches, tail, all sixteen
actual base-address residues paired with all sixteen relative match-start
residues, binary absent/present, natural-text absent/present, selected-pair and
selected-triple dense false positives, sparse false positives followed by a
late match, semantic first/last false positives, and dense match/run
transitions. Every alignment match begins at actual address residue 15 and
crosses a 16-byte vector boundary. Fixture construction and an independent
non-overlapping byte-reference count remain outside the timed region.

This evidence is deliberately limited to selector 11, the exact byte literal
`needle`, cache-resident steady-state calls, and separately labeled
qualification-private first/cached adoption. It does not measure or authorize
AOT compilation, object generation, final linking, process startup, production
adoption latency, another literal or selector, another operation or target, or
general regex AOT. The retained `/usr/bin/time` process reports are resource
records, not a startup-cost decomposition.

Run from this directory on arm64 macOS:

```console
CARGO_TARGET_DIR=/private/tmp/fre-aot-c5-target \
  cargo build --release --locked --offline
/private/tmp/fre-aot-c5-target/release/fre-aot-count-qualified-benchmark
```

The checked-in candidate objects are not authority by themselves. Release
requires a sealed, source-bound run of this package and independent evidence
verification against the exact candidate commit. `PROMOTION.md` defines the
separate Candidate-rooted, independently reviewed atom-only promotion and
post-promotion safe-adapter correctness transaction.

`verify-results.sh` takes externally expected binary and benchmark-source
SHA-256 values plus exactly three fresh-process CSV files. It validates every
raw timing row and its arithmetic, recomputes every median and summary, requires
all 174 process/case medians to beat portable by at least 1.10×, and requires at
least 95% of the 2,784 same-process/case/repetition pairs to win. Each process
has `58 × 16 × 2 = 1,856` raw samples; all summary and pair gates are derived
from their integer elapsed-nanosecond rows. Reported summary rows are never
trusted as authority.
