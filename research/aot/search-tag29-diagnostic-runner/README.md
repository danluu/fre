# Tag-29 topology diagnostic runner

This unsealed Apple-only harness provides early correctness and performance
feedback while the independent qualification controller is constructed. It
consumes the frozen topology projection verbatim and cannot change candidate
membership, routing, thresholds, exclusions, or promotion.

It intentionally lives outside both the static runner and
`search-static-sealer-v1`. Its results are diagnostic only. Formal promotion
requires the separately sealed two-host campaign and repaired analyzer.

Both modes authenticate the frozen projection's domain-separated digest and
exact row count before executing a fixture. Correctness then requires all
123,424 rows, 922 unique literals, 49,248 expected native routes, and 74,176
portable/refusal routes. Timing requires all 3,078 preselected cells and all
808 linked candidates; neither mode accepts a result-derived subset.

```text
fre-external-regex-static-runner correctness FULL_PROJECTION
fre-external-regex-static-runner timing TIMED_PROJECTION TARGET_NS REPETITIONS NEW_OUTPUT
```

The timing mode alternates paired portable/automatic-AOT calls, calibrates both
variants, and uses the larger iteration requirement so the faster variant
reaches the requested per-measurement duration.
