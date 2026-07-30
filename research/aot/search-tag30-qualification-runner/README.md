# Search tag-30 qualification runner

This package is the pre-result, result-blind runner for the immutable tag-30
learned-continuation experiment and its separately frozen broad long-input
policy. Rebar, benchmark output, and campaign results cannot change literal
membership, fixture membership, sharding, routing, gates, or exclusions.

The checked-in campaign contract fixes sixteen nonoverlapping ordinal shards
for each projection. Every invocation authenticates the complete input
projection before executing its assigned half-open range and creates one new
JSONL fragment. A completed fragment contains an authenticated header, every
ordinal in order, and a trailer over the exact row-record bytes.

`universal` correctness calls every admitted V17 object directly, including
below the later production floor. `long-policy` correctness additionally
checks the automatic facade whose authenticated floor is exactly 65,536
bytes. Universal timing is complete mechanism evidence but grants no
production-policy authority; long-policy timing is the only input to the
long-policy performance gates.

Both timing modes use six alternating pairs for a cell in one process. The
runner pins the process to the requested logical CPU, samples that CPU before
and after every measured variant, and rejects a migration. Each recorded
variant must run for at least 400 ms. Guarded fixtures end exactly at a
`PROT_NONE` page; padded fixtures retain the frozen mod-16 address.

```text
fre-search-tag30-qualification-runner \
  correctness CONTRACT (universal|long-policy) PROJECTION \
  SHARD_ID HOST_ID CPU_ID NEW_OUTPUT

fre-search-tag30-qualification-runner \
  timing CONTRACT (universal|long-policy) PROJECTION \
  SHARD_ID HOST_ID CPU_ID NEW_OUTPUT
```

The linked build accepts only a
`fre.aot.search-tag30-qualification-runner-identity.v1` identity, backend tag
30 / `AsimdV17`, candidate policy 15, AOT magic `465245413634001e`, the
unchanged 808-candidate membership authority, and the 65,536-byte automatic
route floor. Without a linked identity Cargo builds only a selector-neutral
test scaffold.
