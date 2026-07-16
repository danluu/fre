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

Validate a coverage-complete draft or final pointwise observation file:

```text
cargo run -p rebar-compare --bin performance-contract -- \
  validate-observations \
  research/rebar/performance/current-main-a1a87d11-contract.json \
  /Users/danluu/dev/fre \
  /absolute/path/to/full344.json \
  /absolute/path/to/observations.json
```

This first unit does not execute a benchmark. The existing KLV timing runner
still needs real `count-captures`, `grep-captures`, and `regex-redux` timing
boundaries, multi-pattern input, allocation/memory collection, and generation
of a 344-row draft before it can produce an artifact accepted by this
contract.
