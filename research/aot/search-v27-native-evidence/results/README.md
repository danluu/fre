# V27 direct linked-AOT evidence

These are complete, non-Rebar matrices produced by the source-first harness at
corpus identity
`63e581915a654928e616ad209d70500a85b37714c1f96d39032fe9ef87521f20`.
Each host ran 2,304 timed cells:

- exact-literal widths 1–32;
- uniform, periodic, clustered, and phase-unique byte topology;
- `Exists`, `SelectedEnd`, and `Span`;
- no match, an early match, and the final legal match; and
- 64 KiB and 1 MiB windows.

Each run also passed 4,608 randomized, untimed semantic cases against both a
scalar oracle and the current `PortableRegex` value API with zero mismatches.
Compilation, audit, assembly, and static linking occur before timing.

## Results

| Host | Overall geomean | V25-fast geomean | V25-fast width ≥17 geomean | width ≥17 p05 | width ≥17 cells ≥1.20x | width ≥17 regressions |
|---|---:|---:|---:|---:|---:|---:|
| Apple M5 Max, macOS 26.6 | 2.002x | 2.717x | 2.759x | 1.255x | 741 / 774 | 7 / 774 |
| AWS C9g, Neoverse-V3, Linux 6.17 | 2.018x | 2.582x | 2.566x | 1.005x | 672 / 774 | 37 / 774 |

The robust production-tail result is stronger. Restricting only by the same
compile-time class (`V25-fast`, width at least 17) and looking at no-match plus
late-match calls gives:

| Host | Tail-scanning geomean | p05 | cells ≥1.20x | regressions |
|---|---:|---:|---:|---:|
| Apple M5 Max | 3.549x | 1.420x | 499 / 516 | 6 / 516 |
| AWS C9g | 3.497x | 1.396x | 506 / 516 | 6 / 516 |

That cross-host agreement supports a portable-prefix plus linked-AOT-tail
route for topology-authenticated V25-fast literals. The prefix retains the
portable early-match strength; the AOT tail handles the broad class where its
gain is large and stable. V8 fallback must not receive the same authority:
uniform and periodic fallback cells contain material regressions on both
hosts.

The result identities are:

- `apple-t6050-v1.json`:
  `823b2c4188e34e37779caa1b96eab5dcffb7f88fbf9a550cf1f4dfaba9a43d30`
- `c9g-neoverse-v3-v1.json`:
  `c15e2743f39f8710a3d76cbb987e379f0493af1b71723d7604a3204f49f4b2bb`

The C9g host exposed ASIMD, SVE, and SVE2. V27/tag40 itself requires ASIMD;
the additional feature exposure is recorded to establish that the same
evidence host can be used for later SVE/SVE2 AOT comparisons.
