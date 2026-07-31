# Search tag-30 broad long-input policy

This is a separate pre-result qualification policy layered on the immutable
tag-30 learned-continuation freeze. It does not weaken or replace the
universal 3,078-cell tag-30 experiment.

The production class is all tag-30-selector-eligible exact byte literals of
width 6 through 32 on full search windows of at least 65,536 bytes. The floor
is a workload-independent amortization boundary shared with the existing
Count AOT production policy: sixteen 4 KiB pages must be scanned before the
native static route is permitted. Pattern spelling, corpus identity, Rebar,
timing, and expected results cannot affect the route.

The derived projection keeps all 123,424 correctness rows. Below-floor rows
must take the portable route; admitted long rows must take tag30. Timing keeps
all 1,458 preselected cells across every eligible width and topology, every
frozen mutation class whose fixture is at or above the floor, both outcomes,
every learned-byte source kind, every literal phase, every logical and
physical alignment, and both guarded and padded mappings. There are no
result-derived exclusions.

Both Apple AArch64 and the C9g Neoverse-V3 host must independently pass:

- exact correctness, route, guarded-boundary, and scalar-oracle closure;
- candidate/portable geometric mean strictly below 0.80 overall and for every
  width, topology, window size, outcome, and learned-source kind;
- no individual cell above 1.05; and
- at least 80% strict paired wins across the complete projection on each host.

Each cell uses six alternating paired repetitions on one logical CPU, and each
variant must run for at least 400 ms. The class grants no production authority
by itself; a later reviewed source change must install the exact route and
retain portable fallback for every nonmember.

Regenerate the procedural projections and summary with:

```sh
python3 research/aot/search-tag30-long-input-policy-v1/derive_projection.py
```
