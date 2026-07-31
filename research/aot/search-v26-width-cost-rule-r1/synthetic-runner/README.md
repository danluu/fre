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
Unit tests pin the byte derivation, population identity, uniqueness,
determinism, per-cell counts, and public-emitter admission.

Candidate/source static parity, KIR/native correctness, and the explicitly
report-only local emission timing command are added only after the separately
implemented `AsimdV26` public backend is available. This scaffold does not run
or infer any V26 timing.
