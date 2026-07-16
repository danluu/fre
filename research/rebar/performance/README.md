# Current-main Rebar performance contract

`current-main-a1a87d11-contract.json` is an executable coverage and reporting
contract, not a timing result. It binds exact canonical main, its independently
reproduced semantic receipt set, all 344 Rust-target rows, all seven Rebar
models, and the lifecycle boundaries that must be reported for each supported
row.

The contract deliberately keeps all 87 unsupported rows in the denominator.
A pointwise observation artifact has exactly one row for every semantic FRE
receipt. Supported rows report every required lifecycle boundary against Rust
regex and RE2; an absent or semantically nonpassing reference remains an
explicit `not-comparable` point with a reason. Unsupported rows retain their
exact semantic reason. A qualification artifact cannot contain `pending`
points, and no aggregate can substitute for a missing or failed point.

Validate only the contract and protected main identity:

```text
cargo run -p rebar-compare --bin performance-contract -- \
  validate-contract \
  research/rebar/performance/current-main-a1a87d11-contract.json \
  /Users/danluu/dev/fre
```

Authenticate the bound full semantic report and its exact 344-row universe:

```text
cargo run -p rebar-compare --bin performance-contract -- \
  validate-semantic \
  research/rebar/performance/current-main-a1a87d11-contract.json \
  /Users/danluu/dev/fre \
  /absolute/path/to/full344.json
```

Generate a new coverage-complete pending draft without running timing:

```text
cargo run -p rebar-compare --bin performance-contract -- \
  generate-draft \
  research/rebar/performance/current-main-a1a87d11-contract.json \
  /Users/danluu/dev/fre \
  /absolute/path/to/full344.json \
  /new/path/current-main-draft.json
```

Generation refuses to overwrite an existing output. The compact JSON contains
exactly 344 sorted semantic job IDs. Each supported row has its contracted
lifecycle boundaries and an explicit Rust/RE2 placeholder. A passing semantic
reference is `pending`; a missing or nonpassing reference is
`not-comparable` with a reason. The generator validates its own output before
publication.

Validate a coverage-complete draft or final pointwise observation file:

```text
cargo run -p rebar-compare --bin performance-contract -- \
  validate-observations \
  research/rebar/performance/current-main-a1a87d11-contract.json \
  /Users/danluu/dev/fre \
  /absolute/path/to/full344.json \
  /absolute/path/to/observations.json
```

These units do not execute a benchmark. The existing KLV timing runner still
needs real `count-captures`, `grep-captures`, and `regex-redux` timing
boundaries, multi-pattern input, allocation/memory collection, and an
authenticated process that replaces draft placeholders with measured points
without altering the fixed row/boundary/comparator universe.
