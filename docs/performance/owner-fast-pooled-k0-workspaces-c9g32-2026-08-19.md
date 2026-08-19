# Owner-fast pooled K0 workspaces: C9g diagnostic

Feature commit `4c06a7fff13fc8af5e87d04530fa47eb336d34d6`
replaces the mutex-only automatic K0 workspace cache with a general
thread-owner pool. The owner thread checks out its retained workspace without
taking the fallback mutex or moving the large workspace value. Non-owner and
reentrant calls use a bounded fallback lane, and concurrent misses construct a
transient bounded workspace instead of serializing the search.

The public call shape does not change: ordinary `PortableRegex` result methods
automatically reuse implementation-owned scratch. Callers do not create a
session or select a benchmark-specific path. The exact benchmarked source is
`574ceb3da1b1dc807182198dede5396294e19f85`; the commits after the feature are
test-only stack fixes and holdout test/receipt maintenance.

## Validation before timing

Several large Rebar regression tests overflowed libtest's default thread stack
on both the feature commit and its parent. They already passed with a 32 MiB
test stack, so the affected tests were moved behind the same explicit
stack-sized thread pattern used by neighboring tests. On the exact benchmarked
source, all 288 runnable Rebar library tests passed (24 asset-dependent tests
were ignored), as did all 7 holdout unit tests and all 4 frozen-suite tests.

## Holdout result

The frozen 19-case non-Rebar holdout ran first on a 32-vCPU AWS C9g instance
with Rust 1.93.0, Rust-regex 1.12.4, and RE2 2025-11-05. It used three warmups
and nine measurements per exact input. Correctness passed 1,014/1,014 FRE
comparisons, 507/507 Rust-regex comparisons, and 507/507 RE2 comparisons.

Ratios are reference/FRE, so larger is better for FRE. Primary metrics include
only `find` and `exists`; selected-end remains diagnostic.

| Comparator | Metric | Prior automatic pool | Owner-fast pool | Change |
| --- | --- | ---: | ---: | ---: |
| Rust-regex | hot primary | 0.447566 | 0.533072 | +19.1% |
| RE2 | hot primary | 0.843327 | 0.996946 | +18.2% |
| Rust-regex | primary common API | 0.506574 | 0.550743 | +8.7% |
| RE2 | primary common API | 0.379803 | 0.412149 | +8.5% |
| Rust-regex | one-shot primary | 0.573361 | 0.568999 | -0.8% |
| RE2 | one-shot primary | 0.171049 | 0.170387 | -0.4% |

The result has the expected shape. The owner fast path improves the reused hot
boundary by about 18–19%, while one-shot performance is effectively unchanged
because it still pays cold construction. FRE reaches near parity with RE2 on
the primary hot aggregate (`0.997x`) but remains about `1.88x` slower than
Rust-regex there (`1 / 0.533`). The primary common-API aggregate remains below
one because it gives equal weight to hot and one-shot points.

## Rebar regression result

Normal Rebar ran after holdout, with fresh preflight and the slowest points
first. It retained 1,152 of 1,220 prepared points, ran one adjacent pair per
point, produced 2,304 successful arms with zero timing errors, and balanced 576
AB with 576 BA points.

| Scope | Prior automatic pool | Owner-fast pool | Change |
| --- | ---: | ---: | ---: |
| Overall | 2.177035 | 2.172796 | -0.2% |
| Rust-regex | 1.386788 | 1.389277 | +0.2% |
| RE2 | 3.802923 | 3.777989 | -0.7% |

These small movements are consistent with a neutral Rebar regression check.
Rebar has only one pair per point, so the table is descriptive and does not
estimate run-to-run variance.

The first Rebar launch stopped before candidate build, preflight, or timing: the
reused comparator deployment intentionally omitted old Cargo/source-cache files
listed by its historical whole-tree manifest. The fresh retry preserved that
failed attempt, authenticated the manifest and build receipt, directly checked
the required Rebar/Rust-regex/RE2 binaries, and then completed the full
campaign.

## Reproduction and limits

The machine-readable aggregate record is
[`owner-fast-pooled-k0-workspaces-c9g32-2026-08-19.json`](owner-fast-pooled-k0-workspaces-c9g32-2026-08-19.json).
The compact external evidence archive is
`fre-owner-fast-pool-574ceb3d-c9g32-results.tar.gz`, SHA-256
`f3f9db2b6fe47c19796ea2049e01c0a0364d8a6d3755eae5ae738de3d5b2c174`.
Raw KLV payloads and build directories are excluded; raw holdout samples,
Rebar timing journals, schedules, receipts, and analyses are included.
The compact package also omits four build executables. Its other 52 holdout
manifest entries match; the packaged driver log differs only by the final
`COMPLETE` line appended after its manifest entry was recorded. Rebar's 31 raw
journal hashes and all analysis hashes independently match.

The before and after runs used independent C9g instances and different source
revisions, so this is not a randomized same-machine A/B. The exact holdout
correctness file is unchanged (`1a37d607...`), but host variance and unrelated
source movement can still affect timing. AOT was not rerun because this change
affects the normal portable K0 workspace pool rather than AOT execution.
