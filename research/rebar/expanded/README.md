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
