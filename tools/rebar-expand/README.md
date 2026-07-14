# `rebar-expand`

`rebar-expand` turns a pinned Rebar checkout into deterministic qualification
inputs for the high-level `rust/regex` and `re2` adapters. It resolves Rebar's
TOML defaults, pattern-file transforms, binary haystack transforms,
engine-specific expected counts and benchmark-model timing contracts.

It is intentionally not a benchmark runner or semantic comparator. Dynamic
engine availability, version receipts, execution success and speed remain
explicitly unresolved in the emitted manifest.

From the workspace root:

```console
cargo run -p rebar-expand --offline -- \
  --checkout /tmp/rebar-fre \
  --rebar-bin target/debug/rebar \
  --expected-revision 463d00f31887e84c38467805b9e3122c314b9521 \
  --output research/rebar/expanded
```

Generation fails if the revision differs, a source cannot be decoded within
the checked resource limits, a path escapes Rebar's input directories, the
normalized job set differs from `rebar measure --list`, or any of seven
representative KLV inputs differs at the byte level. Rebar's dynamic version
column is deliberately removed before the list comparison and hash.

The compact JSON manifest references exact transformed pattern blobs by
SHA-256. Haystacks are not duplicated: the manifest records their exact byte
length and SHA-256 together with the pinned raw source and ordered transform
recipe.

Release qualification includes the slower double-generation test:

```console
cargo test -p rebar-expand --offline \
  pinned_checkout_regeneration_is_deterministic -- --ignored
```
