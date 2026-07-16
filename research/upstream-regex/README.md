# Pinned Rust `regex` conformance inventory

This directory authenticates the raw upstream testdata corpus for Rust
`regex` 1.12.4 at Git revision
`7b96fdc9d5fe6a0cb4efe30e6689b050493fc1e1`. It is the first input layer of a
broader compatibility gate; it is not evidence that FRE executes or passes any
upstream case.

`regex-1.12.4-inventory.json` records every file below upstream `testdata/`,
the SHA-256 and byte length of each source, every decoded `[[test]]` record,
semantic defaults and stable capability axes for each case, and the complete
case-by-adapter obligation count. The payload has its own canonical JSON
SHA-256. Unknown TOML fields, unexpected files, symlinks, a dirty checkout,
the wrong Git revision, duplicate names, malformed expected-match shapes, and
cardinality changes all fail closed.

The pinned inventory contains 31 source files: 26 TOML corpus files and five
Fowler/provenance auxiliaries. The TOML files contain 1,184 raw cases. The
`regex` crate's integration runner loads 1,175 of them; the other nine belong
to `regex-lite.toml` and remain inventoried but are not treated as `regex`
obligations. Fourteen declared adapter surfaces therefore create 16,450
mandatory dispositions.
Inventory payload SHA-256:
`2b590613fc7538181c072c29e34e903dcff7a055d03de00f55482b77c1ed4b06`.
`SHA256SUMS` separately authenticates the checked-in pretty-JSON file bytes.

The adapter contract deliberately has no skip outcome. Every raw case must
receive one explicit disposition for each declared Rust text, Rust bytes, text
set, and bytes set compile/search surface. A future adapter may say that an
upstream case is inapplicable to a particular facade, but it must publish the
typed reason as a receipt instead of filtering the case out.

## Reproduce

Use a clean checkout at the exact revision:

```sh
cargo run -p rust-regex-conformance -- \
  verify /path/to/rust-regex-checkout \
  research/upstream-regex/regex-1.12.4-inventory.json

cargo test -p rust-regex-conformance
cargo clippy -p rust-regex-conformance --all-targets -- -D warnings
```

Regeneration is explicit and writes only the requested manifest path:

```sh
cargo run -p rust-regex-conformance -- \
  generate /path/to/rust-regex-checkout \
  research/upstream-regex/regex-1.12.4-inventory.json
```

## Scope boundary

This unit inventories the upstream TOML/Fowler corpus only. It does not yet:

- execute an FRE adapter or compare observed values;
- inventory the upstream Rust API regression, replacement, searcher, doctest,
  or feature-matrix tests;
- inventory the separate `regex-syntax` and `regex-automata` suites;
- establish constructor-admission, correctness, coverage, performance, or
  release qualification.

Those omissions are repeated inside the authenticated manifest so a complete
input inventory cannot be mistaken for a compatibility result.
