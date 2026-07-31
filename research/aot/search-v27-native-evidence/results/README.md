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

## Exact production composition

The hybrid result files measure the production-shaped composition rather than
inferring it from the direct-call outcome split:

1. the portable engine owns exactly the first 256 candidate starts;
2. its prefix window includes only the `width - 1` bytes needed to finish the
   final prefix candidate;
3. the linked V27 entry starts at candidate 256, making the two candidate-start
   domains disjoint; and
4. only width 17–32 families whose emitted graph is authenticated as
   `V25-fast` enter timing.

That compile-time class contains 43 literal families and 774 timing cells.
Uniform literals are absent by construction because V27 selects the V8
fallback for every uniform topology; this is an explicit structural exclusion,
not a dropped benchmark row. Periodic, clustered, and phase-unique families
that actually select V25-fast are all retained.

| Host | Hybrid geomean | 64 KiB geomean | 1 MiB geomean | no-match geomean / p05 | late-match geomean / p05 | early-match geomean |
|---|---:|---:|---:|---:|---:|---:|
| Apple M5 Max | 2.268x | 2.326x | 2.210x | 3.994x / 1.263x | 3.455x / 1.455x | 0.845x |
| AWS C9g | 2.320x | 2.386x | 2.256x | 4.076x / 1.521x | 3.607x / 1.533x | 0.850x |

Both hybrid runs passed 774 deterministic cells and 1,548 independently
seeded untimed cases with zero mismatches across all three output contracts.
The approximately 15% early-match cost is the small portable-prefix wrapper
cost on a call that returns after only a few dozen bytes; it is not an AOT
tail regression because the tail is not invoked. It should remain visible in
the activation policy rather than being averaged away. Across the complete
equal-weight long-window matrix, the exact composition still exceeds 2.2x on
both hosts.

The hybrid result identities are:

- `apple-t6050-hybrid-v1.json`:
  `30f53b01893c8d9305288c2fa66f45d1d51a4d158ae1db71b394c53bc13a9cad`
- `c9g-neoverse-v3-hybrid-v1.json`:
  `f1257698ca7843f2b05639e30a0f59cb0a1bc6071f1ffa185c7c0b7f2be50915`

## V27 versus V25 identity

The build fails unless every V27 family classified as V25-fast is byte-for-byte
equal to a separately emitted direct V25 image for every output. The exhaustive
evidence-corpus proof covers 192 images (64 families times three outputs) and
compares output, target, source identity, layout, code, rodata, labels, symbols,
relocations, and complete image statistics. Artifact identities are required
to remain different.

This mirrors the emitter's source-level invariant: the V27
`AsimdV25` selection calls the frozen V25 graph emitter directly. V27/tag40 is
the safer production identity even though the executed bytes are identical:
tag40 binds the authenticated topology decision and policy version 17 into the
artifact and auditor contract. Activating direct V25 would move that topology
decision outside the artifact and create a classifier-drift/relabeling risk.
Production should therefore activate V27/tag40 only when its authenticated
selection is V25-fast, not relabel the same bytes as V25 and not extend that
authority to V27's fallback graph.
