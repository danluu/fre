# `fre-holdout`

`fre-holdout` is the standalone runner for the frozen non-Rebar qualification corpus in `../../research/holdout`.

Its modules are kept as explicit stages analogous to a regex implementation pipeline:

1. deserialize and semantically validate the suite contract;
2. deterministically expand explicit, seeded-byte, and repeated-byte generators;
3. authenticate raw files, canonical expansion, and exact counts;
4. execute the pinned Rust-regex byte oracle;
5. adapt the FRE portable facade and classify typed refusals versus faults;
6. emit deterministic per-operation correctness receipts and enforce the semantic gate;
7. optionally emit a separate, non-normative two-engine timing report.

The stages are public where packaging or integration needs them (`authenticate_*`, `expand_manifest`, `run_correctness`, `run_performance`, and `enforce_strict_gate`) and otherwise small private functions with focused unit tests. The candidate adapter is the only layer coupled to FRE error families; generators, authentication, oracle values, coverage, and report schemas can be tested independently.

The runner intentionally does not contain Rebar integration, benchmark tuning, JIT control, or a hidden corpus. Read `../../research/holdout/README.md` for the exact frozen identity, semantic and timing boundaries, current coverage, limitations, and integration commands.
