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
`6c5150a2fc66c7262c0ca308fa164cc6fca78de97ae3dfbc948b53c41ca2a263`.
`SHA256SUMS` separately authenticates the checked-in pretty-JSON file bytes.

The adapter contract deliberately has no skip outcome. Every raw case must
receive one explicit disposition for each declared Rust text, Rust bytes, text
set, and bytes set compile/search surface. A future adapter may say that an
upstream case is inapplicable to a particular facade, but it must publish the
typed reason as a receipt instead of filtering the case out.

The first executable adapter authenticates the same checkout and manifest
again, joins every case to its decoded pattern, byte haystack, bounds, line
terminator and expected capture records, and emits all 16,450 dispositions in
one payload-hashed report. It executes the real `fre::PortableBuilder` Rust
bytes facade for compile and `is_match`, plus `find` when an empty expected
sequence or upstream `match-limit = 1` makes the facade's single-result API a
complete comparator. A theorem-gated `fre::PortableTextBuilder` additionally
executes finite languages only after independent RustText and RustBytes parses
produce the same ordered language and every word is valid UTF-8. Its bounded
non-finite slice requires identical HIRs whose matches are valid UTF-8 and
either positive minimum width or no assertions when nullable. Complete
non-overlapping match iteration uses checked contextual windows and reproduces
Rust's empty-match progression, including UTF-8 scalar boundaries. The first
Rust bytes capture slice materializes persistent-history group records with
exact empty and unmatched slots. The text capture slice admits only an exact
UTF-8-safe HIR shared with an independently parsed same-option byte proof and
filters empty matches inside scalar encodings. Capture Unicode scalar classes
lower through checked canonical UTF-8 byte-range sequences under explicit HIR,
AST, state, and work limits. Rust text sets compose those independently proved
matchers under set-wide bounds. Missing byte sets, capture HIRs outside those
proofs, and unproved text execution remain stable `unsupported` receipts. Inapplicable
upstream surface combinations remain separately typed, and panics become
`fault` receipts without truncating the cross product.

The separate replacement API adapter covers the complete non-TOML
`tests/replace.rs` source at the same pin. It authenticates the published crate
package's VCS receipt, original manifest and complete Rust source file before
executing all 26 named obligations. Each obligation emits a mandatory pass,
mismatch, unsupported or fault receipt; there is no skip/filter disposition.
The executable split is nine literal/`NoExpand` cases, nine capture-template
cases, two functional-replacer cases and six owned/borrowed/`Cow<str>` type
surface cases.

## Reproduce

Use a clean checkout at the exact revision:

```sh
cargo run -p rust-regex-conformance -- \
  verify /path/to/rust-regex-checkout \
  research/upstream-regex/regex-1.12.4-inventory.json

cargo run -p rust-regex-conformance -- run \
  /path/to/rust-regex-checkout \
  research/upstream-regex/regex-1.12.4-inventory.json \
  "$PWD" /tmp/fre-rust-regex-adapter-report.json

cargo test -p rust-regex-conformance
cargo clippy -p rust-regex-conformance --all-targets -- -D warnings

cargo run -p rust-regex-conformance -- run-replacement-api \
  "$HOME/.cargo/registry/src/index.crates.io-1949cf8c6b5b557f/regex-1.12.4" \
  "$PWD" /tmp/fre-rust-regex-replacement-api-report.json

cargo run -p rust-regex-conformance -- verify-replacement-api-report \
  /tmp/fre-rust-regex-replacement-api-report.json
```

Regeneration is explicit and writes only the requested manifest path:

```sh
cargo run -p rust-regex-conformance -- \
  generate /path/to/rust-regex-checkout \
  research/upstream-regex/regex-1.12.4-inventory.json
```

## Scope boundary

The authenticated inventory plus the TOML and replacement adapters do not yet:

- provide general Rust text beyond the proved slices, byte sets, capture
  iteration, or full match iteration;
- produce mandatory reports for the remaining upstream Rust API regression,
  searcher, doctest, or feature-matrix tests;
- inventory the separate `regex-syntax` and `regex-automata` suites;
- establish constructor-admission, correctness, coverage, performance, or
  release qualification.

Those omissions are repeated inside the authenticated manifest so a complete
input inventory cannot be mistaken for a compatibility result.
