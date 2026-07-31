# Search V27 production decision

This decision activates only the self-contained AArch64 Search V27/tag40
machine-code path selected as the frozen V25-fast graph. It does not use LLVM
and does not authorize V27's V8 fallback graph.

## Route

- semantic shape: unanchored, nonempty, capture-free exact byte literal;
- output: `Span`;
- target: little-endian AArch64 AAPCS64 on macOS or Linux with ASIMD;
- backend: tag40 / candidate policy 17;
- authenticated selected graph: V25-fast;
- decoded literal width: 17 through 32 bytes inclusive;
- minimum search window: 65,536 bytes;
- portable prefix: the first 256 candidate starts; and
- native tail: candidate start 256 through the final legal start, disjoint
  from the prefix.

The compiler and independent auditor bind the tag40 topology decision into the
artifact. The production runtime must reject an otherwise valid tag40 image
whose reconstructed selected graph is V8 fallback or V17-fast.

## Evidence and relaxed regression gate

The source-first non-Rebar corpus covers widths 1–32, uniform, periodic,
clustered, and phase-unique byte distributions, all three native output
contracts, no/early/late outcomes, 64 KiB and 1 MiB windows, and randomized
unseen semantic fixtures.

The production-composition subset contains every corpus family that
authenticates as V25-fast at width 17–32: 43 families and 774 timed cells per
host. Uniform literals are structurally ineligible rather than omitted after
timing. Both Apple and C9g runs passed 774 deterministic and 1,548 randomized
semantic comparisons with zero mismatches.

The activation gate is intentionally not a zero-regression rule:

- each host must exceed 1.20x geometric mean over the complete equal-weight
  long-window matrix;
- no-match and late-match fifth percentiles must exceed 1.20x;
- an early-return wrapper cost up to 20% is allowed because the native tail is
  not invoked; and
- semantic mismatches remain zero-tolerance.

Observed hybrid results:

| Host | Overall | 64 KiB | 1 MiB | No-match | Late-match | Early-match |
|---|---:|---:|---:|---:|---:|---:|
| Apple M5 Max | 2.268x | 2.326x | 2.210x | 3.994x | 3.455x | 0.845x |
| AWS C9g Neoverse-V3 | 2.320x | 2.386x | 2.256x | 4.076x | 3.607x | 0.850x |

The build also proves, over 192 images, that every V27 image classified as
V25-fast has the same target, source identity, layout, code, rodata, labels,
symbols, relocations, and statistics as an independently emitted V25 image.
Backend and artifact identities must remain different.

Raw results:

- Apple direct:
  `823b2c4188e34e37779caa1b96eab5dcffb7f88fbf9a550cf1f4dfaba9a43d30`
- C9g direct:
  `c15e2743f39f8710a3d76cbb987e379f0493af1b71723d7604a3204f49f4b2bb`
- Apple hybrid:
  `30f53b01893c8d9305288c2fa66f45d1d51a4d158ae1db71b394c53bc13a9cad`
- C9g hybrid:
  `f1257698ca7843f2b05639e30a0f59cb0a1bc6071f1ffa185c7c0b7f2be50915`
- corpus:
  `63e581915a654928e616ad209d70500a85b37714c1f96d39032fe9ef87521f20`

## Sealed identities

The authority atom uses these domain-separated derivations:

```text
plan preimage =
FRE-SEARCH-V27-PRODUCTION-PLAN-V1|selector=41|backend=40|graph=v25-fast|literal=17..32|window>=65536|portable-prefix=256|output=span|platform=macos,linux
plan identity =
cc5959f0b200cfadf5d4a5561f1676cd3b09cfdbe158adf5538602897f42e1f0

analyzer preimage =
FRE-SEARCH-V27-PRODUCTION-ANALYZER-V1|build=986efbbf3434a23a2bed55cbd3c1cf9ce5dfeb5ee2ac3e16cb52771d063105ae|runner=6b05aed14bfe2a2e43d76e416012bb01cde963ec255d6dccae7a1105d8dfc0e7
analyzer identity =
2fdeb6c5ac7430cdadc6ceceeb2f9bd40108f976e6b12fd225167c1a25ac2724

evidence preimage =
FRE-SEARCH-V27-PRODUCTION-EVIDENCE-V1|apple=30f53b01893c8d9305288c2fa66f45d1d51a4d158ae1db71b394c53bc13a9cad|c9g=f1257698ca7843f2b05639e30a0f59cb0a1bc6071f1ffa185c7c0b7f2be50915|corpus=63e581915a654928e616ad209d70500a85b37714c1f96d39032fe9ef87521f20
evidence identity =
6a176e473aff324b3b4f695a078ff9484744993a18f22f29f38ad0cffa0f5982
```

Default-policy tag40 `Span` manifest identities:

- macOS:
  `8cddb03c39cf95d78d87e43078247ddf5c0348c45361a1fabb36913ace106fe1`
- Linux:
  `0f220e3f4b3b8e659c800349015f6995a46052e74f8edcc844da65613f426f06`

Evidence source checkpoint:

- commit: `20ba79a9fda24e064745915d4a2f9da5777d2c91`
- tree: `d15067eaa25fc033dd4cf33db2e45ea47c465938`
- authorization identity:
  `79842e3d6f7abf3004559a877e3fe229a408f802d87176413d053ea749383edf`
