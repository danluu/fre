# Expanded Rebar qualification inputs

This is a **static input manifest**, not a correctness or speed result. It expands the
pinned Rebar revision `463d00f31887e84c38467805b9e3122c314b9521` for the high-level `rust/regex` and `re2`
adapters. Runtime availability, semantic comparison and timing remain explicitly
unresolved.

- Definition files inventoried: 68
- Benchmark definitions decoded: 360
- Selected jobs: 629 (`rust/regex`: 344, `re2`: 285)
- Excluded definitions retained: 16
- Unique transformed pattern blobs: 3039
- Rebar normalized list check: exact-normalized-job-set-match
- Representative Rebar KLV byte checks: 7 (exact-byte-match)

`manifest.json` is compact JSON. `manifest.sha256` authenticates it. Exact
transformed patterns live under `blobs/`; transformed haystacks are identified by
byte length and SHA-256 plus a reproducible source/transform recipe, avoiding a
duplicate copy of Rebar's large data files.

The generated manifest and blobs are deliberately not tracked. A clean source
checkout therefore skips the two full-artifact tests during the ordinary
workspace test suite. After regenerating this directory, authenticate the full
fixture explicitly with:

```sh
cargo test --locked --offline -p rebar-expand --lib \
  generated_artifact_round_trips_and_covers_representative_definitions -- --ignored
cargo test --locked --offline -p rebar-expand --lib \
  every_referenced_pattern_blob_has_exact_content_hash -- --ignored
```
