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
matchers under set-wide bounds. Rust byte sets compose bounded byte matchers,
preserve arbitrary-byte haystacks and publish matching pattern IDs in stable
source order. Capture HIRs outside the proved slices and unproved text execution
remain stable `unsupported` receipts. Inapplicable upstream surface combinations
remain separately typed, and panics become `fault` receipts without truncating
the cross product.

The separate replacement API adapter covers the complete non-TOML
`tests/replace.rs` source at the same pin. It authenticates the published crate
package's VCS receipt, original manifest and complete Rust source file before
executing all 26 named obligations. Each obligation emits a mandatory pass,
mismatch, unsupported or fault receipt; there is no skip/filter disposition.
The executable split is nine literal/`NoExpand` cases, nine capture-template
cases, two functional-replacer cases and six owned/borrowed/`Cow<str>` type
surface cases.

The pattern-searcher adapter covers the complete non-TOML
`tests/searcher.rs` source at the same pin. It authenticates the published
crate identity and complete Rust source file before executing all 11 named
obligations through FRE's aggregate search-step API. Each obligation emits a
mandatory pass, mismatch, unsupported or fault receipt, including empty,
zero-width, rejected-range and Unicode step sequences.

The public-doctest adapter authenticates the published package receipt,
original manifest, `README.md`, and all seven Rust source files that contribute
default-feature rustdoc tests. It derives and hashes every applicable fenced
obligation from those exact bytes: five README examples, 56 builder examples,
two bytes-module examples, 23 crate-level examples, 60 examples for each
string/bytes regex module, and 18 for each string/bytes set module. The one
upstream `ignore` doctest remains an obligation; non-Rust `text` and `toml`
fences are the only source-authenticated non-doctest blocks. All 242 obligations
receive a mandatory pass, mismatch, unsupported or fault receipt. The initial
FRE execution slice passes 127, with 115 explicit unsupported receipts and no
mismatch or fault. It exercises builder configuration, text/byte search,
complete iteration, split/splitn, capture metadata and set behavior without
re-counting the separately owned replacement, searcher or misc test suites.
The derived obligation-inventory SHA-256 is
`028754b101949945211bfb067736739d703d2979719f9f7186d5b282955f70cb`.

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

cargo run -p rust-regex-conformance -- run-misc-regression-api \
  "$HOME/.cargo/registry/src/index.crates.io-1949cf8c6b5b557f/regex-1.12.4" \
  "$PWD" /tmp/fre-rust-regex-misc-regression-api-report.json

cargo run -p rust-regex-conformance -- verify-misc-regression-api-report \
  /tmp/fre-rust-regex-misc-regression-api-report.json

cargo run -p rust-regex-conformance -- run-searcher-api \
  "$HOME/.cargo/registry/src/index.crates.io-1949cf8c6b5b557f/regex-1.12.4" \
  "$PWD" /tmp/fre-rust-regex-searcher-api-report.json

cargo run -p rust-regex-conformance -- verify-searcher-api-report \
  /tmp/fre-rust-regex-searcher-api-report.json

cargo run -p rust-regex-conformance -- run-doctest-api \
  "$HOME/.cargo/registry/src/index.crates.io-1949cf8c6b5b557f/regex-1.12.4" \
  "$PWD" /tmp/fre-rust-regex-doctest-api-report.json

cargo run -p rust-regex-conformance -- verify-doctest-api-report \
  /tmp/fre-rust-regex-doctest-api-report.json
```

Regeneration is explicit and writes only the requested manifest path:

```sh
cargo run -p rust-regex-conformance -- \
  generate /path/to/rust-regex-checkout \
  research/upstream-regex/regex-1.12.4-inventory.json
```

## Scope boundary

The authenticated inventory plus the TOML, replacement, searcher, misc and
public-doctest adapters
do not yet:

- provide general Rust text beyond the proved slices, byte sets, capture
  full match iteration;
- produce mandatory reports for the upstream Cargo feature matrix;
- inventory the separate `regex-syntax` and `regex-automata` suites;
- establish constructor-admission, correctness, coverage, performance, or
  release qualification.

Those omissions are repeated inside the authenticated manifest so a complete
input inventory cannot be mistaken for a compatibility result.
