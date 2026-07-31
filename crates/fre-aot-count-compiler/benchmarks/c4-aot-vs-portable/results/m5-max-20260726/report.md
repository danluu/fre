# Count-v2 linked AOT versus current portable Count

On this Apple M5 Max run, the linked Count-v2 AOT entry was faster in all
eight median comparisons. It was 1.22–1.44× faster for sparse-present,
absent, and tail cases, and about 27.2× faster for dense non-overlapping
matches. It also won all 128 same-case, same-repetition engine pairs.

| Case | Bytes | Count | AOT median | Portable median | Portable/AOT | AOT GiB/s | Portable GiB/s |
|---|---:|---:|---:|---:|---:|---:|---:|
| present-64k | 65,536 | 3 | 1,212.585 ns | 1,592.753 ns | 1.3135× | 50.3347 | 38.3205 |
| absent-64k | 65,536 | 0 | 1,040.792 ns | 1,477.132 ns | 1.4192× | 58.6430 | 41.3200 |
| dense-64k | 65,536 | 10,922 | 7,680.217 ns | 208,644.511 ns | 27.1665× | 7.9471 | 0.2925 |
| tail-64k | 65,536 | 1 | 1,049.561 ns | 1,506.673 ns | 1.4355× | 58.1531 | 40.5099 |
| present-1m | 1,048,576 | 3 | 17,256.836 ns | 21,013.992 ns | 1.2177× | 56.5899 | 46.4720 |
| absent-1m | 1,048,576 | 0 | 17,069.664 ns | 20,900.383 ns | 1.2244× | 57.2104 | 46.7246 |
| dense-1m | 1,048,576 | 174,762 | 122,238.609 ns | 3,324,050.453 ns | 27.1931× | 7.9890 | 0.2938 |
| tail-1m | 1,048,576 | 1 | 16,879.555 ns | 20,769.203 ns | 1.2304× | 57.8548 | 47.0197 |

## Method

- Frozen benchmark source: commit
  `e3555e96d168d0ce1d5d39a3ac5a4abbf03c6b56`, tree
  `4c4a8054431a332b360505d8384d1a630488458a`.
- Frozen C3 implementation: commit
  `7848e392eca6ff928f90fa88eece3068c69e771f`, object SHA-256
  `8db1da7410ae42dfa797a2e0c69b80436796c744f4786395c2a32458780897ec`.
- The same optimized arm64 executable measured both engines. Its SHA-256 was
  `2508ef09a65629c4de7513c1cbbc34c46cd5f1a6a954dd9e6a190316434ba5ab`.
- Each case had 16 repetitions. Eight used AOT-first order and eight used
  portable-first order. Each engine/case/repetition scanned 64 MiB in total.
- Fixtures were built and validated before timing. `present` has three sparse
  matches, `absent` has none, `dense` repeats `needle`, and `tail` has one
  match at the last possible start.
- The portable side called the current exact-literal
  `AggregateCountRegex::count_value` path with unlimited exact-literal
  reducer limits. The AOT side called the linked C3 machine-code entry with
  its audited status/result ABI.
- The fail-fast timing coordinator admitted the wave at
  `2026-07-27T04:53:31Z` and released it at `04:53:41Z`; it did not wait for
  global idleness or stop other work.

The 64 MiB sample total repeats the same 64 KiB or 1 MiB fixture, so these are
cache-resident steady-state comparisons, not sustained-DRAM bandwidth
measurements.

## Compile and link costs

| Phase | Median |
|---|---:|
| Current portable Count construction | 5.717 µs |
| Focused AOT object/expectation/prelink emission | 41.145 µs |
| Final-image glue/receipt emission | 12.839 µs |
| Clang driver compilation + immutable-segment final link | 33.599 ms |

The focused compiler and glue component medians sum to approximately
53.983 µs, about 9.44× the measured portable construction cost. This is not
an end-to-end source qualification number: planner and claim production were
precomputed and excluded. The Clang number includes C driver compilation,
linking, and the platform's normal executable finalization. All compile and
link costs were measured separately and are excluded from steady-state rows.

## Scope and caveats

The AOT number deliberately measures the raw linked entry that a successfully
verified final-image handle would call. It excludes one-time runtime adoption
and per-call policy checks. The production qualification table remains
literally empty, so this result is performance evidence and does not activate
or authorize the AOT path.

The focused AOT compiler emits the arm64 implementation and Mach-O objects
directly; it does not use LLVM. Rust and the current portable comparison were
compiled by rustc 1.93.0, whose reported LLVM version was 21.1.8. Results are
specific to the pinned source, artifacts, toolchain, machine, and fixtures.

The complete 16-repetition sample set, checksums, execution order, source and
binary hashes, and component-cost samples are in `raw.csv`. Host and timing
admission details are in `environment.txt`.
