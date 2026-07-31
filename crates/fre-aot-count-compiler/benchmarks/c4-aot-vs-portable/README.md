# Count-v2 AOT versus portable benchmark

This standalone, lockfile-pinned package compares the C3 arm64 implementation
entry linked into the benchmark executable with the current FRE
`AggregateCountRegex::count_value` exact-literal path.

The benchmark constructs all fixtures before timing. For each of the eight
present/absent/dense/tail × 64 KiB/1 MiB cases, it measures 16 repetitions and
alternates AOT-first with portable-first order. Every sample scans 64 MiB. It
also reports portable construction, focused AOT emission from precomputed
claims, final-image glue emission, and Clang driver-compile/link costs as
separate phases.

The AOT steady-state number is deliberately the raw verified-entry target; it
does not include runtime adoption or per-call policy checks. The production
qualification table remains empty, so this benchmark is performance evidence,
not activation authority.

Reproduce from this directory on arm64 macOS:

```console
CARGO_TARGET_DIR=/private/tmp/fre-aot-count-benchmark-target \
  cargo build --release --locked --offline
/private/tmp/fre-aot-count-benchmark-target/release/fre-aot-count-benchmark all
```

Use the repository resource coordinator for both build and timing commands.
