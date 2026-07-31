# Search V26 fresh synthetic runner

This standalone crate materializes the population frozen by
`../preregistration-v1.json`. It has no corpus or result-file input. For every
width, output contract, and accepted slot, it derives SHA-256-domain bytes and
advances the hash ordinal until the public Search V17 emitter admits the exact
literal. The compact population identity binds both the accepted slot and the
source ordinal.

Generate a compact summary without performance timing:

```sh
cargo run --manifest-path \
  research/aot/search-v26-width-cost-rule-r1/synthetic-runner/Cargo.toml \
  --release -- summary
```

Use `population` instead of `summary` to include all 1,296 literal records.
`static` enforces exact V17 graph parity at widths 6 through 8, exact V25
graph parity at widths 9 through 32, tag-39/AOT-magic distinction, and routing
boundaries. `correctness` publishes V26 locally and differentially checks all
7,776 literal/window/output cases against the safe Kernel IR oracle. Unit
tests pin the byte derivation, population identity, uniqueness, determinism,
per-cell counts, geometry, and public-emitter admission.

`emission-timing` is a separate, report-only cold compiler measurement. It
prepares KIR outside the clock, performs two untimed candidate/source warmup
pairs, then records the arithmetic median of eleven paired full-population
emission batches with alternating order. It never publishes or invokes
machine code, refuses non-release builds, and its result is not an acceptance
gate. Search performance execution belongs to a separately sealed one-shot
runner and receipt.
