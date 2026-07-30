# Search V9 broad-deployment matrix

This is a deterministic, non-Rebar comparison of separately authenticated
Search V8/tag 8, Search V9/tag 22, and the current portable exact-literal
`memmem::Finder`. V9 adds an exact first-candidate check before entering the
otherwise unchanged V8 graph. Construction and publication happen outside
timing. Each timed native call retains the same checked window and
literal-resource preflight as the static AOT facade. The CSV `engine` field
names the exact backend tag, so every fixture supports V9/V8 and V9/portable
paired comparisons.

The fourth engine is the screen-trained broad-routing candidate. Literal
widths 2 through 32 and checked windows of at least 4,093 bytes use one
authoritative full-window preflight, portable search for exactly the first 256
candidate starts, and V9 for the tail beginning at candidate start 256.
Portable prefix end is `tail_start + literal_width - 1`, so a match beginning
at candidate 255 is owned wholly by the prefix while candidate 256 is owned
wholly by V9. Width 1 and smaller windows stay entirely portable.

The split was fixed before looking at results:

- screen seeds: `a55100017e23914d`, `f11700023c84d6a9`,
  `6b473a9de12085cf`, `c2e957148ab63d01`
- held-out seeds: `8d1974b2c63e50af`, `d3a52f916c48b7e0`,
  `39f06c82b517e4ad`, `e7812d5a94c360bf`
- widths: every integer width from 1 through 32 bytes
- literal shapes: high entropy, repeated, periodic, binary
- screen sizes: 257, 1,021, 4,093, 16,381, 65,521, 262,139,
  1,048,573 bytes
- held-out sizes: 4,093, 65,521, 1,048,573 bytes
- topology: absent random/filler, early/middle/tail/dense hits,
  first-byte-dense absence, repeated near misses before a tail hit, binary
  tail hit, nonzero-window absence/tail hit, an exact match at `window_start`,
  and a forced V9 selected-byte hit whose full equality fails
- alignment: residues 0, 1, 7, and 15 in screening; every residue 0 through
  15 in held-out measurement

The held-out phase is not a parameterized seed escape hatch: the binary accepts
only the two seed sets above.

`early` is explicitly candidate start 64, not `window_start`; only
`first_candidate_exact` witnesses V9's new immediate-return path.

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

Validate exact fixture/repetition pairing and summarize median ratios with:

```sh
python3 research/aot/search-v8-broad-deploy/analyze.py \
  screen screen-*.csv > screen-analysis.json
```

Ratios are denominated so values above one favor the engine named after
`over`: `v8_over_v9` favors V9 and `portable_over_v9` favors V9. The analyzer
fails closed on missing engines, duplicate shards, repetition gaps, or paired
semantic/checksum/iteration mismatches.

Four seeds times four shapes provide 16 development literals and 16 unopened
held-out literals at every width.

The screen gates were fixed before the expanded screen. V9/V8 geometric mean
at `first_candidate_exact` must be at least 1.20; V9/V8 outside that scenario
must be at least 0.98. Only eligible tail-owned long-scan cells contribute to
the AOT speedup claim. For their contiguous 2..32 aggregate and independently
for every width, shape, and long-scan scenario, `hybrid_ns / portable_ns`
geometric mean must be strictly below 0.80, at least 80% of cells must win,
p90 must be at most 1.00, the maximum cell must be at most 1.25, and there
must be at least 100 observations. Eligible prefix-owned
early/dense/first-candidate cells and all ineligible cells are parity-only:
geometric mean at most 1.02, p90 at most 1.05, maximum cell at most 1.25, and
at least 100 observations. Held-out promotion will use the same frozen policy
and gates, not select another prefix or floor.
