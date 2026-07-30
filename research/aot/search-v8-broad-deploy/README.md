# Search V9 broad-deployment matrix

This is a deterministic, non-Rebar comparison of separately authenticated
Search V8/tag 8, Search V9/tag 22, and the current portable exact-literal
`memmem::Finder`. V9 adds an exact first-candidate check before entering the
otherwise unchanged V8 graph. Construction and publication happen outside
timing. Each timed native call retains the same checked window and
literal-resource preflight as the static AOT facade. The CSV `engine` field
names the exact backend tag, so every fixture supports V9/V8 and V9/portable
paired comparisons.

The split was fixed before looking at results:

- screen seeds: `a55100017e23914d`, `f11700023c84d6a9`
- held-out seeds: `8d1974b2c63e50af`, `d3a52f916c48b7e0`
- widths: 1, 2, 3, 4, 5, 6, 8, 12, 16, 24, 32 bytes
- literal shapes: high entropy, repeated, periodic, binary
- screen sizes: 257, 1,021, 4,093, 16,381, 65,521, 262,139,
  1,048,573 bytes
- held-out sizes: 4,093, 65,521, 1,048,573 bytes
- topology: absent random/filler, early/middle/tail/dense hits,
  first-byte-dense absence, repeated near misses before a tail hit, binary
  tail hit, nonzero-window absence/tail hit
- alignment: residues 0, 1, 7, and 15 in screening; every residue 0 through
  15 in held-out measurement

The held-out phase is not a parameterized seed escape hatch: the binary accepts
only the two seed sets above.

Build and run one shard:

```sh
cargo build --release --manifest-path \
  research/aot/search-v8-broad-deploy/Cargo.toml
research/aot/search-v8-broad-deploy/target/release/fre-search-v8-broad-deploy \
  screen 0 8 3 > screen-0.csv
```

Arguments are `PHASE SHARD SHARDS TARGET_MILLISECONDS`. Run disjoint shards
concurrently, then concatenate one header and all data rows. `heldout` uses
seven repetitions per engine; `confirm` uses the same held-out matrix with
twelve repetitions.
