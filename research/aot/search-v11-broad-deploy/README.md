# Search V11 broad development screen

This screen carries the already-frozen candidate-independent mutation
inventory into separately authenticated Search V10/tag 23 and Search V11/tag
24 machine code. V11 keeps the five-column schema but reserves both literal
endpoints when the packed pair omits them. The portable baseline remains
`memmem::Finder`. Construction, independent whole-template audit, and
strict-W^X publication happen outside timing. Each timed native call retains
the same checked window and literal-resource preflight as the static AOT
facade.

The fourth engine is the development broad-routing candidate. Literal widths
2 through 32 and checked windows of at least 4,093 bytes use one authoritative
full-window preflight, portable search for exactly the first 256 candidate
starts, and V11 for the disjoint tail. Width 1 and smaller windows stay
entirely portable.

This binary is development-only and mechanically accepts only `screen`. It
cannot open or generate heldout data. The screen crosses:

- four deterministic seeds;
- every literal width from 1 through 32 bytes;
- entropy, repeated, periodic, and binary literals;
- 257, 1,021, 4,093, 16,381, 65,521, 262,139, and 1,048,573-byte haystacks;
- absent, early, middle, tail, dense, nonzero-window, binary, and alignment
  topologies;
- repeated wrong-first and wrong-final near misses as independent scenarios;
- for every width 2 through 32, a candidate-independent repeated near-miss
  stream for every literal byte offset, followed by one exact tail match;
- alignments 0, 1, 7, and 15.

`early` uses candidate start 64. Only `first_candidate_exact` witnesses the
immediate-return path.

Build and run one shard:

```sh
cargo build --release --manifest-path \
  research/aot/search-v11-broad-deploy/Cargo.toml
research/aot/search-v11-broad-deploy/target/release/fre-search-v11-broad-deploy \
  screen 0 8 3 > screen-0.csv
```

Arguments are `PHASE SHARD SHARDS TARGET_MILLISECONDS`; `PHASE` must be
`screen`. The target must be at least 3ms so isolated 1ms timing outliers
cannot authorize a candidate envelope. Run disjoint shards concurrently, then
analyze all shard CSVs:

```sh
python3 research/aot/search-v11-broad-deploy/analyze.py \
  screen screen-*.csv > screen-analysis.json
```

Ratios above one favor the denominator: `v10_over_v11` favors V11 and
`portable_over_v11` favors V11. The analyzer fails closed on missing engines,
duplicate shards, repetition gaps, or paired semantic/checksum/iteration
mismatches. It additionally fails closed unless every mutation offset exists
for every seed/width/shape/size cell. Aggregate mutation performance and the
worst width/offset geometric mean are separate predeclared gates, so favorable
offsets cannot hide a pathological unselected byte. Individual maximum ratios
remain diagnostic; structural gates use p90/p99 and the worst width/offset
geometric mean. Prefix-owned and ineligible fixed costs report both ratios and
absolute nanoseconds, with a predeclared 3ns median / 4ns p90 overhead cap.

No result from this development binary is production authority or heldout
evidence.
