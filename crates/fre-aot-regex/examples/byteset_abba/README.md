# Exact ByteSet ABBA qualification

This diagnostic compares the exact parent `fd310800` with candidate
`e243ed2f`. Both binaries use the same additive example overlay. The candidate
build alone enables `fre_byteset_candidate_receipt`, which exposes the new
public receipt to metadata validation without changing production code.

The unchanged `--atomic-choice-grammar` matrix contains two generator seeds,
eight ByteSet cardinalities, eight single-literal control widths, three window
sizes, four positions, four densities, and four deterministic haystack
rotations. Each of the four timed phases uses 8 warmup rounds, 5 trials, a
1-MiB nominal byte budget, at least 32 searches, and a 5-ms calibration floor.

Collection order is frozen as:

1. parent, upstream then native;
2. candidate, native then upstream;
3. candidate, upstream then native;
4. parent, native then upstream.

The collector treats phase output as opaque bytes. It invokes the scorer only
after the metadata phase and all four ABBA phases have been atomically renamed,
hashed, and covered by `COLLECTION_COMPLETE` and `SEALED_PHASES.sha256`.

The scorer requires:

- candidate/parent Rust-normalized ByteSet geometric mean at least 1.05;
- every cardinality/window/density/position intersection at least 0.95;
- single-literal controls between 0.90 and 1.10 overall and at least 0.85 for
  every width/window group;
- parent and candidate repeatability between 0.90 and 1.10 for each family.

Every scored group also reports candidate/Rust and parent/Rust absolute ratios.
The candidate ByteSet eligibility set comes only from authenticated receipt and
pass rows; source names are pairing identities, never compiler policy.

Run the already frozen package with:

```sh
/absolute/frozen/root/scripts/collect_and_score.sh /absolute/empty/output
```
